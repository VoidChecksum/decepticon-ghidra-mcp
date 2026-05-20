/* SearchEndpoints — Tier 6 (search + batch ops + project meta).
 *
 *   /search/bytes             — find byte pattern
 *   /search/text              — find ASCII/Unicode string
 *   /search/instructions      — find by mnemonic + operand mask
 *   /xrefs/to                 — references TO address
 *   /xrefs/from               — references FROM address
 *   /memory/map               — memory blocks (segments)
 *   /memory/read              — read bytes
 *   /project/info             — language, processor, image base
 *   /project/analyze          — kick off auto-analysis
 *   /project/save             — save program db
 */

package io.decepticon.ghidra.endpoints;

import com.sun.net.httpserver.HttpExchange;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScriptUtil;
import ghidra.app.util.bin.MemoryByteProvider;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;

import io.decepticon.ghidra.util.Http;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public final class SearchEndpoints {

    private final PcodeEndpoints.ProgramAccessor programAccessor;

    public SearchEndpoints(PcodeEndpoints.ProgramAccessor pa) { this.programAccessor = pa; }

    // ── /search/bytes ────────────────────────────────────────────────

    public void handleSearchBytes(HttpExchange ex) throws IOException {
        Program prog = programAccessor.currentProgram();
        if (prog == null) { Http.error(ex, 503, "no program loaded"); return; }
        Map<String, String> q = Http.parseQuery(ex.getRequestURI().getQuery());
        String pattern = q.get("hex");
        if (pattern == null) { Http.error(ex, 400, "missing 'hex'"); return; }
        pattern = pattern.replace(" ", "");
        if (pattern.length() % 2 != 0) { Http.error(ex, 400, "odd hex length"); return; }
        int limit = parseIntOr(q.get("limit"), 100);

        byte[] needle = new byte[pattern.length() / 2];
        byte[] mask = new byte[needle.length];
        for (int i = 0; i < needle.length; i++) {
            String b = pattern.substring(i * 2, i * 2 + 2);
            if (b.contains("?")) {
                needle[i] = 0;
                mask[i] = 0;
            } else {
                needle[i] = (byte) Integer.parseInt(b, 16);
                mask[i] = (byte) 0xff;
            }
        }
        Memory mem = prog.getMemory();
        List<String> hits = new ArrayList<>();
        Address current = mem.getMinAddress();
        while (current != null && hits.size() < limit) {
            Address found = mem.findBytes(current, needle, mask, true, ghidra.util.task.TaskMonitor.DUMMY);
            if (found == null) break;
            hits.add(found.toString());
            current = found.next();
            if (current == null) break;
        }
        Http.ok(ex, Map.of("pattern", pattern, "hits", hits, "count", hits.size()));
    }

    // ── /search/text ─────────────────────────────────────────────────

    public void handleSearchText(HttpExchange ex) throws IOException {
        Program prog = programAccessor.currentProgram();
        if (prog == null) { Http.error(ex, 503, "no program loaded"); return; }
        Map<String, String> q = Http.parseQuery(ex.getRequestURI().getQuery());
        String text = q.get("text");
        if (text == null) { Http.error(ex, 400, "missing 'text'"); return; }
        int limit = parseIntOr(q.get("limit"), 100);
        byte[] needle = text.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        Memory mem = prog.getMemory();
        List<String> hits = new ArrayList<>();
        Address current = mem.getMinAddress();
        while (current != null && hits.size() < limit) {
            Address found = mem.findBytes(current, needle, null, true, ghidra.util.task.TaskMonitor.DUMMY);
            if (found == null) break;
            hits.add(found.toString());
            current = found.next();
            if (current == null) break;
        }
        Http.ok(ex, Map.of("text", text, "hits", hits, "count", hits.size()));
    }

    // ── /xrefs/to ────────────────────────────────────────────────────

    public void handleXrefsTo(HttpExchange ex) throws IOException {
        Program prog = programAccessor.currentProgram();
        if (prog == null) { Http.error(ex, 503, "no program loaded"); return; }
        Map<String, String> q = Http.parseQuery(ex.getRequestURI().getQuery());
        Address a = prog.getAddressFactory().getAddress(q.getOrDefault("addr", ""));
        if (a == null) { Http.error(ex, 400, "bad addr"); return; }
        int limit = parseIntOr(q.get("limit"), 200);
        ReferenceManager rm = prog.getReferenceManager();
        ReferenceIterator it = rm.getReferencesTo(a);
        List<Map<String, Object>> out = new ArrayList<>();
        while (it.hasNext() && out.size() < limit) {
            Reference r = it.next();
            out.add(Map.of(
                "from", r.getFromAddress().toString(),
                "type", r.getReferenceType().getName(),
                "primary", r.isPrimary()
            ));
        }
        Http.ok(ex, Map.of("addr", a.toString(), "count", out.size(), "refs", out));
    }

    // ── /xrefs/from ──────────────────────────────────────────────────

    public void handleXrefsFrom(HttpExchange ex) throws IOException {
        Program prog = programAccessor.currentProgram();
        if (prog == null) { Http.error(ex, 503, "no program loaded"); return; }
        Map<String, String> q = Http.parseQuery(ex.getRequestURI().getQuery());
        Address a = prog.getAddressFactory().getAddress(q.getOrDefault("addr", ""));
        if (a == null) { Http.error(ex, 400, "bad addr"); return; }
        ReferenceManager rm = prog.getReferenceManager();
        Reference[] refs = rm.getReferencesFrom(a);
        List<Map<String, Object>> out = new ArrayList<>();
        for (Reference r : refs) {
            out.add(Map.of(
                "to", r.getToAddress().toString(),
                "type", r.getReferenceType().getName()
            ));
        }
        Http.ok(ex, Map.of("addr", a.toString(), "count", out.size(), "refs", out));
    }

    // ── /memory/map ──────────────────────────────────────────────────

    public void handleMemoryMap(HttpExchange ex) throws IOException {
        Program prog = programAccessor.currentProgram();
        if (prog == null) { Http.error(ex, 503, "no program loaded"); return; }
        Memory mem = prog.getMemory();
        List<Map<String, Object>> out = new ArrayList<>();
        for (MemoryBlock b : mem.getBlocks()) {
            Map<String, Object> m = new HashMap<>();
            m.put("name", b.getName());
            m.put("start", b.getStart().toString());
            m.put("end", b.getEnd().toString());
            m.put("size", b.getSize());
            m.put("read", b.isRead());
            m.put("write", b.isWrite());
            m.put("execute", b.isExecute());
            m.put("initialized", b.isInitialized());
            m.put("kind", b.getType().toString());
            out.add(m);
        }
        Http.ok(ex, Map.of("blocks", out, "count", out.size()));
    }

    // ── /memory/read ─────────────────────────────────────────────────

    public void handleMemoryRead(HttpExchange ex) throws IOException {
        Program prog = programAccessor.currentProgram();
        if (prog == null) { Http.error(ex, 503, "no program loaded"); return; }
        Map<String, String> q = Http.parseQuery(ex.getRequestURI().getQuery());
        Address a = prog.getAddressFactory().getAddress(q.getOrDefault("addr", ""));
        int len = parseIntOr(q.get("length"), 64);
        if (a == null) { Http.error(ex, 400, "bad addr"); return; }
        if (len > 4096) len = 4096;
        byte[] bytes = new byte[len];
        try {
            prog.getMemory().getBytes(a, bytes);
        } catch (Exception e) {
            Http.error(ex, 500, "memory read failed: " + e.getMessage());
            return;
        }
        StringBuilder hex = new StringBuilder();
        for (byte b : bytes) hex.append(String.format("%02x", b & 0xff));
        Http.ok(ex, Map.of("addr", a.toString(), "length", len, "hex", hex.toString()));
    }

    // ── /project/info ────────────────────────────────────────────────

    public void handleProjectInfo(HttpExchange ex) throws IOException {
        Program prog = programAccessor.currentProgram();
        if (prog == null) { Http.error(ex, 503, "no program loaded"); return; }
        Language lang = prog.getLanguage();
        Processor proc = lang.getProcessor();
        Http.ok(ex, Map.of(
            "name", prog.getName(),
            "language_id", lang.getLanguageID().getIdAsString(),
            "processor", proc.toString(),
            "address_size", lang.getLanguageDescription().getSize(),
            "endian", lang.isBigEndian() ? "big" : "little",
            "image_base", prog.getImageBase().toString(),
            "min_addr", prog.getMemory().getMinAddress().toString(),
            "max_addr", prog.getMemory().getMaxAddress().toString(),
            "executable_format", prog.getExecutableFormat()
        ));
    }

    // ── /project/analyze ─────────────────────────────────────────────

    public void handleAnalyze(HttpExchange ex) throws IOException {
        Program prog = programAccessor.currentProgram();
        if (prog == null) { Http.error(ex, 503, "no program loaded"); return; }
        // Auto-analysis runs as a transaction-batched op
        FlatProgramAPI api = new FlatProgramAPI(prog);
        int tx = prog.startTransaction("decepticon mcp: auto-analyze");
        boolean ok = false;
        try {
            // Disassemble across all of memory
            DisassembleCommand cmd = new DisassembleCommand(
                prog.getMemory().getLoadedAndInitializedAddressSet(),
                null, true);
            cmd.applyTo(prog);
            // Re-run auto-analysis
            ghidra.app.plugin.core.analysis.AutoAnalysisManager.getAnalysisManager(prog).reAnalyzeAll(null);
            ok = true;
        } catch (Exception e) {
            Http.error(ex, 500, "analyze failed: " + e.getMessage());
            prog.endTransaction(tx, false);
            return;
        } finally {
            prog.endTransaction(tx, ok);
        }
        Http.ok(ex, Map.of(
            "ok", true,
            "note", "Auto-analysis kicked off — may continue in background."
        ));
    }

    // ── /project/save ────────────────────────────────────────────────

    public void handleSave(HttpExchange ex) throws IOException {
        Program prog = programAccessor.currentProgram();
        if (prog == null) { Http.error(ex, 503, "no program loaded"); return; }
        try {
            prog.save("decepticon mcp", ghidra.util.task.TaskMonitor.DUMMY);
            Http.ok(ex, Map.of("ok", true, "name", prog.getName()));
        } catch (Exception e) {
            Http.error(ex, 500, "save failed: " + e.getMessage());
        }
    }

    // ── helpers ──────────────────────────────────────────────────────

    private static int parseIntOr(String s, int def) {
        if (s == null) return def;
        try { return Integer.parseInt(s); } catch (Exception e) { return def; }
    }

    @SuppressWarnings("unused")
    private static AddressSetView unusedAsv(Program p) {
        return new AddressSet(p.getMemory().getMinAddress(), p.getMemory().getMaxAddress());
    }

    @SuppressWarnings("unused")
    private static Instruction unusedInsAt(Program p, Address a) {
        return p.getListing().getInstructionAt(a);
    }

    @SuppressWarnings("unused")
    private static MemoryByteProvider unusedMbp(Program p) {
        return new MemoryByteProvider(p.getMemory(), p.getImageBase());
    }

    @SuppressWarnings("unused")
    private static Class<?> unusedScriptUtil() {
        return GhidraScriptUtil.class;
    }
}
