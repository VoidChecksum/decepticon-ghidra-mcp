/* ListingEndpoints — Tier 13: listing + code units.
 *
 *   /listing/instructions          — paginated instructions in range
 *   /listing/get_instruction_at    — disassembled mnemonic at addr
 *   /listing/get_data_at           — defined data at addr
 *   /listing/create_instruction    — force disassemble single addr
 *   /listing/create_data           — define data at addr w/ type
 *   /listing/clear                 — clearCodeUnits over range
 *   /listing/disassemble_range     — kick disassembler over range
 *   /listing/get_string_at         — read defined string value
 *   /listing/set_fallthrough       — override fallthrough at instruction
 */

package io.decepticon.ghidra.endpoints;

import com.sun.net.httpserver.HttpExchange;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;

import io.decepticon.ghidra.util.Http;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public final class ListingEndpoints {

    private final PcodeEndpoints.ProgramAccessor pa;

    public ListingEndpoints(PcodeEndpoints.ProgramAccessor pa) { this.pa = pa; }

    private static DataType findType(DataTypeManager dtm, String name) {
        if (name == null) return null;
        DataType d = dtm.getDataType(name);
        if (d != null) return d;
        ArrayList<DataType> hits = new ArrayList<>();
        dtm.findDataTypes(name, hits);
        return hits.isEmpty() ? null : hits.get(0);
    }

    // ── /listing/instructions ────────────────────────────────────────

    public void handleInstructions(HttpExchange ex) throws IOException {
        Program prog = pa.currentProgram();
        if (prog == null) { Http.error(ex, 503, "no program loaded"); return; }
        Map<String, String> q = Http.parseQuery(ex.getRequestURI().getQuery());
        Address start = prog.getAddressFactory().getAddress(q.getOrDefault("start", ""));
        Address end = prog.getAddressFactory().getAddress(q.getOrDefault("end", ""));
        int limit = parseIntOr(q.get("limit"), 200);
        if (start == null) { Http.error(ex, 400, "missing 'start'"); return; }
        Listing l = prog.getListing();
        InstructionIterator it = end != null
            ? l.getInstructions(new AddressSet(start, end), true)
            : l.getInstructions(start, true);
        List<Map<String, Object>> out = new ArrayList<>();
        while (it.hasNext() && out.size() < limit) {
            Instruction ins = it.next();
            out.add(Map.of(
                "addr", ins.getAddress().toString(),
                "mnemonic", ins.getMnemonicString(),
                "repr", ins.toString(),
                "length", ins.getLength()
            ));
        }
        Http.ok(ex, Map.of("count", out.size(), "instructions", out));
    }

    // ── /listing/get_instruction_at ──────────────────────────────────

    public void handleGetInstructionAt(HttpExchange ex) throws IOException {
        Program prog = pa.currentProgram();
        if (prog == null) { Http.error(ex, 503, "no program loaded"); return; }
        Map<String, String> q = Http.parseQuery(ex.getRequestURI().getQuery());
        Address a = prog.getAddressFactory().getAddress(q.getOrDefault("addr", ""));
        if (a == null) { Http.error(ex, 400, "bad addr"); return; }
        Instruction ins = prog.getListing().getInstructionAt(a);
        if (ins == null) { Http.error(ex, 404, "no instruction at addr"); return; }
        Map<String, Object> m = new HashMap<>();
        m.put("addr", ins.getAddress().toString());
        m.put("mnemonic", ins.getMnemonicString());
        m.put("repr", ins.toString());
        m.put("length", ins.getLength());
        m.put("flow_type", ins.getFlowType().getName());
        m.put("num_operands", ins.getNumOperands());
        List<String> operands = new ArrayList<>();
        for (int i = 0; i < ins.getNumOperands(); i++) operands.add(ins.getDefaultOperandRepresentation(i));
        m.put("operands", operands);
        Http.ok(ex, m);
    }

    // ── /listing/get_data_at ─────────────────────────────────────────

    public void handleGetDataAt(HttpExchange ex) throws IOException {
        Program prog = pa.currentProgram();
        if (prog == null) { Http.error(ex, 503, "no program loaded"); return; }
        Map<String, String> q = Http.parseQuery(ex.getRequestURI().getQuery());
        Address a = prog.getAddressFactory().getAddress(q.getOrDefault("addr", ""));
        if (a == null) { Http.error(ex, 400, "bad addr"); return; }
        Data d = prog.getListing().getDataAt(a);
        if (d == null) { Http.error(ex, 404, "no defined data at addr"); return; }
        Map<String, Object> m = new HashMap<>();
        m.put("addr", d.getAddress().toString());
        m.put("type", d.getDataType().getName());
        m.put("length", d.getLength());
        Object v = d.getValue();
        m.put("value", v != null ? v.toString() : null);
        m.put("default_repr", d.getDefaultValueRepresentation());
        m.put("is_array", d.isArray());
        m.put("is_pointer", d.isPointer());
        m.put("num_components", d.getNumComponents());
        Http.ok(ex, m);
    }

    // ── /listing/create_instruction ──────────────────────────────────

    public void handleCreateInstruction(HttpExchange ex) throws IOException {
        Program prog = pa.currentProgram();
        if (prog == null) { Http.error(ex, 503, "no program loaded"); return; }
        Map<String, String> q = Http.parseQuery(ex.getRequestURI().getQuery());
        Address a = prog.getAddressFactory().getAddress(q.getOrDefault("addr", ""));
        if (a == null) { Http.error(ex, 400, "bad addr"); return; }
        DisassembleCommand cmd = new DisassembleCommand(a, null, true);
        int tx = prog.startTransaction("decepticon mcp: listing/create_instruction");
        boolean applied = false;
        try {
            applied = cmd.applyTo(prog);
        } finally {
            prog.endTransaction(tx, applied);
        }
        Instruction ins = prog.getListing().getInstructionAt(a);
        Map<String, Object> m = new HashMap<>();
        m.put("addr", a.toString());
        m.put("applied", applied);
        if (ins != null) m.put("instruction", ins.toString());
        Http.ok(ex, m);
    }

    // ── /listing/create_data ─────────────────────────────────────────

    public void handleCreateData(HttpExchange ex) throws IOException {
        Program prog = pa.currentProgram();
        if (prog == null) { Http.error(ex, 503, "no program loaded"); return; }
        Map<String, String> q = Http.parseQuery(ex.getRequestURI().getQuery());
        Address a = prog.getAddressFactory().getAddress(q.getOrDefault("addr", ""));
        String type = q.get("type");
        if (a == null || type == null) { Http.error(ex, 400, "need 'addr' + 'type'"); return; }
        DataType dt = findType(prog.getDataTypeManager(), type);
        if (dt == null) { Http.error(ex, 404, "no type " + type); return; }
        Listing l = prog.getListing();
        int tx = prog.startTransaction("decepticon mcp: listing/create_data");
        boolean ok = false;
        String error = null;
        try {
            l.clearCodeUnits(a, a.add(dt.getLength() - 1L), false);
            l.createData(a, dt);
            ok = true;
        } catch (Exception e) {
            error = e.getClass().getSimpleName() + ": " + e.getMessage();
        } finally {
            prog.endTransaction(tx, ok);
        }
        if (!ok) { Http.error(ex, 500, error); return; }
        Http.ok(ex, Map.of("addr", a.toString(), "type", dt.getName(), "length", dt.getLength()));
    }

    // ── /listing/clear ───────────────────────────────────────────────

    public void handleClear(HttpExchange ex) throws IOException {
        Program prog = pa.currentProgram();
        if (prog == null) { Http.error(ex, 503, "no program loaded"); return; }
        Map<String, String> q = Http.parseQuery(ex.getRequestURI().getQuery());
        Address start = prog.getAddressFactory().getAddress(q.getOrDefault("start", ""));
        Address end = prog.getAddressFactory().getAddress(q.getOrDefault("end", ""));
        boolean clearContext = "true".equalsIgnoreCase(q.getOrDefault("clear_context", "false"));
        if (start == null || end == null) { Http.error(ex, 400, "need 'start' + 'end'"); return; }
        int tx = prog.startTransaction("decepticon mcp: listing/clear");
        try { prog.getListing().clearCodeUnits(start, end, clearContext); }
        finally { prog.endTransaction(tx, true); }
        Http.ok(ex, Map.of("start", start.toString(), "end", end.toString(), "cleared", true));
    }

    // ── /listing/disassemble_range ───────────────────────────────────

    public void handleDisassembleRange(HttpExchange ex) throws IOException {
        Program prog = pa.currentProgram();
        if (prog == null) { Http.error(ex, 503, "no program loaded"); return; }
        Map<String, String> q = Http.parseQuery(ex.getRequestURI().getQuery());
        Address start = prog.getAddressFactory().getAddress(q.getOrDefault("start", ""));
        Address end = prog.getAddressFactory().getAddress(q.getOrDefault("end", ""));
        if (start == null || end == null) { Http.error(ex, 400, "need 'start' + 'end'"); return; }
        DisassembleCommand cmd = new DisassembleCommand(new AddressSet(start, end), null, true);
        int tx = prog.startTransaction("decepticon mcp: listing/disassemble_range");
        boolean ok = false;
        try { ok = cmd.applyTo(prog); }
        finally { prog.endTransaction(tx, ok); }
        Http.ok(ex, Map.of("start", start.toString(), "end", end.toString(), "ok", ok,
            "msg", cmd.getStatusMsg() == null ? "" : cmd.getStatusMsg()));
    }

    // ── /listing/get_string_at ───────────────────────────────────────

    public void handleGetStringAt(HttpExchange ex) throws IOException {
        Program prog = pa.currentProgram();
        if (prog == null) { Http.error(ex, 503, "no program loaded"); return; }
        Map<String, String> q = Http.parseQuery(ex.getRequestURI().getQuery());
        Address a = prog.getAddressFactory().getAddress(q.getOrDefault("addr", ""));
        if (a == null) { Http.error(ex, 400, "bad addr"); return; }
        Data d = prog.getListing().getDataAt(a);
        if (d == null) { Http.error(ex, 404, "no data at addr"); return; }
        Object v = d.getValue();
        if (!(v instanceof String s)) {
            Http.error(ex, 404, "data at addr is not a string (got " + (v == null ? "null" : v.getClass().getSimpleName()) + ")"); return;
        }
        Http.ok(ex, Map.of("addr", a.toString(), "value", s, "length", s.length(), "type", d.getDataType().getName()));
    }

    // ── /listing/set_fallthrough ─────────────────────────────────────

    public void handleSetFallthrough(HttpExchange ex) throws IOException {
        Program prog = pa.currentProgram();
        if (prog == null) { Http.error(ex, 503, "no program loaded"); return; }
        Map<String, String> q = Http.parseQuery(ex.getRequestURI().getQuery());
        Address a = prog.getAddressFactory().getAddress(q.getOrDefault("addr", ""));
        Address fallthrough = prog.getAddressFactory().getAddress(q.getOrDefault("fallthrough", ""));
        if (a == null) { Http.error(ex, 400, "bad addr"); return; }
        Instruction ins = prog.getListing().getInstructionAt(a);
        if (ins == null) { Http.error(ex, 404, "no instruction at addr"); return; }
        int tx = prog.startTransaction("decepticon mcp: listing/set_fallthrough");
        try {
            ins.setFallThrough(fallthrough);  // null clears the override
        } finally {
            prog.endTransaction(tx, true);
        }
        Http.ok(ex, Map.of("addr", a.toString(),
            "fallthrough", fallthrough == null ? "(cleared)" : fallthrough.toString()));
    }

    @SuppressWarnings("unused")
    private static CodeUnit unusedCu() { return null; }

    private static int parseIntOr(String s, int def) {
        if (s == null) return def;
        try { return Integer.parseInt(s); } catch (Exception e) { return def; }
    }
}
