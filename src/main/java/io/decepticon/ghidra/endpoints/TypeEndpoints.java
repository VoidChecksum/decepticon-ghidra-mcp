/* TypeEndpoints — Tier 4 (type recovery + struct work).
 *
 *   /types/list                — all data types in the program
 *   /types/get_struct          — struct layout by name
 *   /types/apply_struct_at     — apply a struct at an address
 *   /types/recover_function    — HighFunction-driven type inference
 *   /types/list_at_addr        — datatype currently at addr
 */

package io.decepticon.ghidra.endpoints;

import com.sun.net.httpserver.HttpExchange;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;

import io.decepticon.ghidra.util.Http;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

public final class TypeEndpoints {

    private final PcodeEndpoints.ProgramAccessor programAccessor;

    public TypeEndpoints(PcodeEndpoints.ProgramAccessor pa) { this.programAccessor = pa; }

    // ── /types/list ──────────────────────────────────────────────────

    public void handleList(HttpExchange ex) throws IOException {
        Program prog = programAccessor.currentProgram();
        if (prog == null) { Http.error(ex, 503, "no program loaded"); return; }
        Map<String, String> q = Http.parseQuery(ex.getRequestURI().getQuery());
        int limit = parseIntOr(q.get("limit"), 500);
        String prefix = q.get("prefix");
        DataTypeManager dtm = prog.getDataTypeManager();
        List<Map<String, Object>> out = new ArrayList<>();
        Iterator<DataType> it = dtm.getAllDataTypes();
        while (it.hasNext() && out.size() < limit) {
            DataType dt = it.next();
            if (prefix != null && !dt.getName().startsWith(prefix)) continue;
            out.add(Map.of(
                "name", dt.getName(),
                "path", dt.getPathName(),
                "length", dt.getLength(),
                "kind", dt.getClass().getSimpleName()
            ));
        }
        Http.ok(ex, Map.of("count", out.size(), "types", out));
    }

    // ── /types/get_struct ────────────────────────────────────────────

    public void handleGetStruct(HttpExchange ex) throws IOException {
        Program prog = programAccessor.currentProgram();
        if (prog == null) { Http.error(ex, 503, "no program loaded"); return; }
        Map<String, String> q = Http.parseQuery(ex.getRequestURI().getQuery());
        String name = q.get("name");
        if (name == null) { Http.error(ex, 400, "missing 'name'"); return; }
        DataType dt = prog.getDataTypeManager().getDataType(name);
        if (dt == null) {
            // Try by lookup across categories
            var it = prog.getDataTypeManager().getAllStructures();
            while (it.hasNext()) {
                DataType cand = it.next();
                if (cand.getName().equals(name)) { dt = cand; break; }
            }
        }
        if (!(dt instanceof Composite c)) {
            Http.error(ex, 404, "no Composite type named: " + name);
            return;
        }
        List<Map<String, Object>> fields = new ArrayList<>();
        for (DataTypeComponent dc : c.getDefinedComponents()) {
            fields.add(Map.of(
                "offset", dc.getOffset(),
                "field_name", dc.getFieldName() != null ? dc.getFieldName() : ("_pad" + dc.getOffset()),
                "type", dc.getDataType().getName(),
                "length", dc.getLength(),
                "comment", dc.getComment() != null ? dc.getComment() : ""
            ));
        }
        Http.ok(ex, Map.of(
            "name", c.getName(),
            "length", c.getLength(),
            "alignment", c.getAlignment(),
            "fields", fields
        ));
    }

    // ── /types/apply_struct_at ───────────────────────────────────────

    public void handleApplyStructAt(HttpExchange ex) throws IOException {
        Program prog = programAccessor.currentProgram();
        if (prog == null) { Http.error(ex, 503, "no program loaded"); return; }
        Map<String, String> q = Http.parseQuery(ex.getRequestURI().getQuery());
        Address a = prog.getAddressFactory().getAddress(q.getOrDefault("addr", ""));
        String typeName = q.get("type");
        if (a == null || typeName == null) {
            Http.error(ex, 400, "need 'addr' + 'type'");
            return;
        }
        DataType dt = prog.getDataTypeManager().getDataType(typeName);
        if (dt == null) {
            var it = prog.getDataTypeManager().getAllStructures();
            while (it.hasNext()) {
                DataType cand = it.next();
                if (cand.getName().equals(typeName)) { dt = cand; break; }
            }
        }
        if (dt == null) {
            Http.error(ex, 404, "type not found: " + typeName);
            return;
        }
        Listing lst = prog.getListing();
        int tx = prog.startTransaction("decepticon mcp: apply_struct_at");
        boolean ok = false;
        String error = null;
        try {
            lst.clearCodeUnits(a, a.add(dt.getLength() - 1L), false);
            lst.createData(a, dt);
            ok = true;
        } catch (Exception e) {
            error = e.getClass().getSimpleName() + ": " + e.getMessage();
        } finally {
            prog.endTransaction(tx, ok);
        }
        if (!ok) { Http.error(ex, 500, error); return; }
        Http.ok(ex, Map.of(
            "addr", a.toString(),
            "type", dt.getName(),
            "length", dt.getLength()
        ));
    }

    // ── /types/recover_function ──────────────────────────────────────

    public void handleRecoverFunction(HttpExchange ex) throws IOException {
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
            DecompileResults res = decomp.decompileFunction(fn, 60, null);
            if (res == null || !res.decompileCompleted()) {
                Http.error(ex, 500, "decompile failed");
                return;
            }
            HighFunction hf = res.getHighFunction();
            if (hf == null) { Http.error(ex, 500, "no high function"); return; }
            Map<String, Object> rec = new HashMap<>();
            rec.put("function", fn.getName());
            rec.put("addr", a.toString());
            // Return type
            rec.put("return_type", hf.getFunctionPrototype().getReturnType().getName());
            // Parameters
            List<Map<String, Object>> params = new ArrayList<>();
            int n = hf.getFunctionPrototype().getNumParams();
            for (int i = 0; i < n; i++) {
                HighSymbol sym = hf.getFunctionPrototype().getParam(i);
                params.add(Map.of(
                    "name", sym.getName(),
                    "type", sym.getDataType().getName(),
                    "size", sym.getSize()
                ));
            }
            rec.put("params", params);
            // Locals
            List<Map<String, Object>> locals = new ArrayList<>();
            Iterator<HighSymbol> it = hf.getLocalSymbolMap().getSymbols();
            while (it.hasNext()) {
                HighSymbol s = it.next();
                if (s.isParameter()) continue;
                locals.add(Map.of(
                    "name", s.getName(),
                    "type", s.getDataType().getName(),
                    "size", s.getSize()
                ));
            }
            rec.put("locals", locals);
            Http.ok(ex, rec);
        } finally {
            decomp.dispose();
        }
    }

    // ── /types/list_at_addr ──────────────────────────────────────────

    public void handleListAtAddr(HttpExchange ex) throws IOException {
        Program prog = programAccessor.currentProgram();
        if (prog == null) { Http.error(ex, 503, "no program loaded"); return; }
        Map<String, String> q = Http.parseQuery(ex.getRequestURI().getQuery());
        Address a = prog.getAddressFactory().getAddress(q.getOrDefault("addr", ""));
        if (a == null) { Http.error(ex, 400, "bad addr"); return; }
        Data d = prog.getListing().getDataAt(a);
        if (d == null) {
            Http.ok(ex, Map.of("addr", a.toString(), "type", "undefined", "length", 0));
            return;
        }
        Http.ok(ex, Map.of(
            "addr", a.toString(),
            "type", d.getDataType().getName(),
            "length", d.getLength(),
            "is_array", d.isArray(),
            "is_struct", d.getDataType() instanceof Structure
        ));
    }

    private static int parseIntOr(String s, int def) {
        if (s == null) return def;
        try { return Integer.parseInt(s); } catch (Exception e) { return def; }
    }
}
