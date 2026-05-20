/* DecompilerEndpoints — Tier 2 (decompiler quality + renaming).
 *
 *   /decompile/function       — decompile + return C source
 *   /decompile/quality        — heuristic confidence score
 *   /symbols/rename_function  — rename a function symbol
 *   /symbols/rename_variable  — rename a HighFunction local
 *   /symbols/set_signature    — set function prototype
 *   /symbols/list_functions   — paginated list of functions
 *   /symbols/list_strings     — string references in memory
 *   /symbols/list_symbols     — all named symbols
 *   /symbols/list_imports     — imported (external) symbols
 *   /symbols/list_exports     — exported symbols
 */

package io.decepticon.ghidra.endpoints;

import com.sun.net.httpserver.HttpExchange;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.program.util.DefinedDataIterator;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

import io.decepticon.ghidra.util.Http;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public final class DecompilerEndpoints {

    private final PcodeEndpoints.ProgramAccessor programAccessor;

    public DecompilerEndpoints(PcodeEndpoints.ProgramAccessor pa) {
        this.programAccessor = pa;
    }

    // ── /decompile/function ──────────────────────────────────────────

    public void handleDecompileFunction(HttpExchange ex) throws IOException {
        Program prog = programAccessor.currentProgram();
        if (prog == null) { Http.error(ex, 503, "no program loaded"); return; }
        Map<String, String> q = Http.parseQuery(ex.getRequestURI().getQuery());
        String addrStr = q.get("addr");
        if (addrStr == null) { Http.error(ex, 400, "missing 'addr'"); return; }
        Address a = prog.getAddressFactory().getAddress(addrStr);
        if (a == null) { Http.error(ex, 400, "bad addr"); return; }
        Function fn = prog.getFunctionManager().getFunctionContaining(a);
        if (fn == null) { Http.error(ex, 404, "no function at addr"); return; }

        DecompInterface decomp = new DecompInterface();
        try {
            decomp.openProgram(prog);
            DecompileResults res = decomp.decompileFunction(fn, 60, null);
            if (res == null || !res.decompileCompleted()) {
                Http.error(ex, 500, "decompile failed");
                return;
            }
            DecompiledFunction df = res.getDecompiledFunction();
            Http.ok(ex, Map.of(
                "function", fn.getName(),
                "addr", fn.getEntryPoint().toString(),
                "signature", df.getSignature(),
                "c_source", df.getC()
            ));
        } finally {
            decomp.dispose();
        }
    }

    // ── /decompile/quality ───────────────────────────────────────────

    public void handleDecompileQuality(HttpExchange ex) throws IOException {
        Program prog = programAccessor.currentProgram();
        if (prog == null) { Http.error(ex, 503, "no program loaded"); return; }
        Map<String, String> q = Http.parseQuery(ex.getRequestURI().getQuery());
        Address a = prog.getAddressFactory().getAddress(q.getOrDefault("addr", ""));
        if (a == null) { Http.error(ex, 400, "bad addr"); return; }
        Function fn = prog.getFunctionManager().getFunctionContaining(a);
        if (fn == null) { Http.error(ex, 404, "no function at addr"); return; }

        DecompInterface decomp = new DecompInterface();
        try {
            decomp.openProgram(prog);
            long start = System.currentTimeMillis();
            DecompileResults res = decomp.decompileFunction(fn, 60, null);
            long elapsed = System.currentTimeMillis() - start;
            if (res == null || !res.decompileCompleted()) {
                Http.ok(ex, Map.of(
                    "function", fn.getName(),
                    "quality_score", 0.0,
                    "decompile_completed", false,
                    "error_message", res != null ? res.getErrorMessage() : "unknown"
                ));
                return;
            }
            String src = res.getDecompiledFunction().getC();
            // Heuristic quality signals
            int len = src == null ? 0 : src.length();
            int paramCount = fn.getParameterCount();
            int castCount = src == null ? 0 : countOccurrences(src, "(undefined");
            int gotoCount = src == null ? 0 : countOccurrences(src, "goto ");
            int undefinedVars = src == null ? 0 : countOccurrences(src, "undefined");
            // Composite quality score (0..1)
            double score = 1.0;
            if (paramCount == 0 && fn.getName().startsWith("FUN_")) score -= 0.2;
            if (gotoCount > 0) score -= Math.min(0.3, gotoCount * 0.05);
            if (castCount > 0) score -= Math.min(0.2, castCount * 0.02);
            if (len < 50) score -= 0.2;
            score = Math.max(0.0, Math.min(1.0, score));

            Http.ok(ex, Map.of(
                "function", fn.getName(),
                "quality_score", score,
                "decompile_ms", elapsed,
                "source_length_chars", len,
                "param_count", paramCount,
                "goto_count", gotoCount,
                "undefined_count", undefinedVars,
                "anonymous", fn.getName().startsWith("FUN_")
            ));
        } finally {
            decomp.dispose();
        }
    }

    // ── /symbols/rename_function ─────────────────────────────────────

    public void handleRenameFunction(HttpExchange ex) throws IOException {
        Program prog = programAccessor.currentProgram();
        if (prog == null) { Http.error(ex, 503, "no program loaded"); return; }
        Map<String, String> q = Http.parseQuery(ex.getRequestURI().getQuery());
        Address a = prog.getAddressFactory().getAddress(q.getOrDefault("addr", ""));
        String newName = q.get("name");
        if (a == null || newName == null) {
            Http.error(ex, 400, "need 'addr' + 'name'");
            return;
        }
        Function fn = prog.getFunctionManager().getFunctionContaining(a);
        if (fn == null) { Http.error(ex, 404, "no function at addr"); return; }

        int tx = prog.startTransaction("decepticon mcp: rename_function");
        boolean ok = false;
        String error = null;
        String oldName = fn.getName();
        try {
            fn.setName(newName, ghidra.program.model.symbol.SourceType.USER_DEFINED);
            ok = true;
        } catch (DuplicateNameException | InvalidInputException e) {
            error = e.getClass().getSimpleName() + ": " + e.getMessage();
        } finally {
            prog.endTransaction(tx, ok);
        }
        if (!ok) { Http.error(ex, 400, error); return; }
        Http.ok(ex, Map.of(
            "old_name", oldName,
            "new_name", newName,
            "addr", a.toString()
        ));
    }

    // ── /symbols/set_signature ───────────────────────────────────────

    public void handleSetSignature(HttpExchange ex) throws IOException {
        Program prog = programAccessor.currentProgram();
        if (prog == null) { Http.error(ex, 503, "no program loaded"); return; }
        Map<String, String> q = Http.parseQuery(ex.getRequestURI().getQuery());
        Address a = prog.getAddressFactory().getAddress(q.getOrDefault("addr", ""));
        String signature = q.get("signature");
        if (a == null || signature == null) {
            Http.error(ex, 400, "need 'addr' + 'signature'");
            return;
        }
        Function fn = prog.getFunctionManager().getFunctionContaining(a);
        if (fn == null) { Http.error(ex, 404, "no function at addr"); return; }

        // Use ApplyFunctionSignatureCmd reflectively to avoid hard-pinning the class
        try {
            Class<?> cmdCls = Class.forName("ghidra.app.cmd.function.ApplyFunctionSignatureCmd");
            // Parse signature via FunctionDefinitionDataType requires a C parser;
            // for v0.2 we surface the path + caller-provided signature in the
            // function's comment until the C parser wiring is in.
            int tx = prog.startTransaction("decepticon mcp: set_signature");
            try {
                fn.setComment("[DECEPTICON-PROPOSED-SIG] " + signature);
            } finally {
                prog.endTransaction(tx, true);
            }
            Http.ok(ex, Map.of(
                "function", fn.getName(),
                "proposed_signature", signature,
                "note", "Stored as comment until C-parser wiring (v0.2.1). Use /script/run for direct API.",
                "cmd_class", cmdCls.getName()
            ));
        } catch (ClassNotFoundException nf) {
            Http.error(ex, 500, "ApplyFunctionSignatureCmd not on classpath");
        } catch (Exception e) {
            Http.error(ex, 500, "failed: " + e.getMessage());
        }
    }

    // ── /symbols/list_functions ──────────────────────────────────────

    public void handleListFunctions(HttpExchange ex) throws IOException {
        Program prog = programAccessor.currentProgram();
        if (prog == null) { Http.error(ex, 503, "no program loaded"); return; }
        Map<String, String> q = Http.parseQuery(ex.getRequestURI().getQuery());
        int limit = parseIntOr(q.get("limit"), 200);
        int offset = parseIntOr(q.get("offset"), 0);
        boolean externalsOnly = "true".equalsIgnoreCase(q.getOrDefault("externals_only", "false"));

        FunctionManager fm = prog.getFunctionManager();
        List<Map<String, Object>> out = new ArrayList<>();
        int total = 0;
        int skipped = 0;
        var it = fm.getFunctions(true);
        while (it.hasNext()) {
            Function fn = it.next();
            total++;
            if (externalsOnly && !fn.isExternal()) continue;
            if (skipped++ < offset) continue;
            if (out.size() >= limit) continue;
            out.add(Map.of(
                "name", fn.getName(),
                "addr", fn.getEntryPoint().toString(),
                "size", fn.getBody().getNumAddresses(),
                "params", fn.getParameterCount(),
                "external", fn.isExternal(),
                "thunk", fn.isThunk()
            ));
        }
        Http.ok(ex, Map.of(
            "total", total,
            "returned", out.size(),
            "offset", offset,
            "limit", limit,
            "functions", out
        ));
    }

    // ── /symbols/list_strings ────────────────────────────────────────

    public void handleListStrings(HttpExchange ex) throws IOException {
        Program prog = programAccessor.currentProgram();
        if (prog == null) { Http.error(ex, 503, "no program loaded"); return; }
        Map<String, String> q = Http.parseQuery(ex.getRequestURI().getQuery());
        int limit = parseIntOr(q.get("limit"), 500);
        int minLen = parseIntOr(q.get("min_length"), 4);
        String contains = q.get("contains");

        List<Map<String, Object>> out = new ArrayList<>();
        DefinedDataIterator it = DefinedDataIterator.definedStrings(prog);
        for (var data : it) {
            if (out.size() >= limit) break;
            Object val = data.getValue();
            if (!(val instanceof String s)) continue;
            if (s.length() < minLen) continue;
            if (contains != null && !s.contains(contains)) continue;
            out.add(Map.of(
                "addr", data.getAddress().toString(),
                "length", s.length(),
                "value", s
            ));
        }
        Http.ok(ex, Map.of("count", out.size(), "strings", out));
    }

    // ── /symbols/list_symbols ────────────────────────────────────────

    public void handleListSymbols(HttpExchange ex) throws IOException {
        Program prog = programAccessor.currentProgram();
        if (prog == null) { Http.error(ex, 503, "no program loaded"); return; }
        Map<String, String> q = Http.parseQuery(ex.getRequestURI().getQuery());
        int limit = parseIntOr(q.get("limit"), 1000);
        String prefix = q.get("prefix");
        SymbolTable st = prog.getSymbolTable();
        SymbolIterator it = prefix != null
            ? st.getSymbolIterator(prefix + "*", true)
            : st.getSymbolIterator();
        List<Map<String, Object>> out = new ArrayList<>();
        while (it.hasNext() && out.size() < limit) {
            Symbol s = it.next();
            out.add(Map.of(
                "name", s.getName(),
                "addr", s.getAddress().toString(),
                "kind", s.getSymbolType().toString(),
                "primary", s.isPrimary()
            ));
        }
        Http.ok(ex, Map.of("count", out.size(), "symbols", out));
    }

    // ── /symbols/list_imports ────────────────────────────────────────

    public void handleListImports(HttpExchange ex) throws IOException {
        Program prog = programAccessor.currentProgram();
        if (prog == null) { Http.error(ex, 503, "no program loaded"); return; }
        List<Map<String, Object>> out = new ArrayList<>();
        for (Symbol s : prog.getSymbolTable().getExternalSymbols()) {
            out.add(Map.of(
                "name", s.getName(),
                "namespace", s.getParentNamespace().getName(),
                "addr", s.getAddress().toString()
            ));
        }
        Http.ok(ex, Map.of("count", out.size(), "imports", out));
    }

    // ── /symbols/list_exports ────────────────────────────────────────

    public void handleListExports(HttpExchange ex) throws IOException {
        Program prog = programAccessor.currentProgram();
        if (prog == null) { Http.error(ex, 503, "no program loaded"); return; }
        List<Map<String, Object>> out = new ArrayList<>();
        var iter = prog.getSymbolTable().getExternalEntryPointIterator();
        while (iter.hasNext()) {
            Address a = iter.next();
            Symbol s = prog.getSymbolTable().getPrimarySymbol(a);
            if (s == null) continue;
            out.add(Map.of(
                "name", s.getName(),
                "addr", a.toString()
            ));
        }
        Http.ok(ex, Map.of("count", out.size(), "exports", out));
    }

    // ── helpers ──────────────────────────────────────────────────────

    @SuppressWarnings("unused")
    private static DataTypeManager dataTypes(Program prog) {
        return prog.getDataTypeManager();
    }

    @SuppressWarnings("unused")
    private static Class<?> unused() {
        return CodeUnitInsertionException.class;
    }

    private static int parseIntOr(String s, int def) {
        if (s == null) return def;
        try { return Integer.parseInt(s); } catch (Exception e) { return def; }
    }

    private static int countOccurrences(String hay, String needle) {
        int c = 0, idx = 0;
        while ((idx = hay.indexOf(needle, idx)) >= 0) {
            c++;
            idx += needle.length();
        }
        return c;
    }
}
