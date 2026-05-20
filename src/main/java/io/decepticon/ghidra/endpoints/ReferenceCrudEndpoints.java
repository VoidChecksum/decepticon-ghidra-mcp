/* ReferenceCrudEndpoints — Tier 11: reference CRUD.
 *
 *   /refs/create               — addMemoryReference from src to dst
 *   /refs/delete               — remove ref
 *   /refs/set_primary          — mark a ref as primary
 *   /refs/in_range             — refs whose src/dst lies in a range
 *   /refs/by_type              — flow / data / external / stack / mem
 *   /refs/count_to             — count refs to addr
 *   /refs/count_from           — count refs from addr
 *   /refs/external_only        — only ExternalReferences
 */

package io.decepticon.ghidra.endpoints;

import com.sun.net.httpserver.HttpExchange;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;

import io.decepticon.ghidra.util.Http;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public final class ReferenceCrudEndpoints {

    private final PcodeEndpoints.ProgramAccessor pa;

    public ReferenceCrudEndpoints(PcodeEndpoints.ProgramAccessor pa) { this.pa = pa; }

    private static RefType refTypeFromName(String name) {
        return switch (name == null ? "data" : name.toLowerCase()) {
            case "unconditional_call" -> RefType.UNCONDITIONAL_CALL;
            case "conditional_call"   -> RefType.CONDITIONAL_CALL;
            case "computed_call"      -> RefType.COMPUTED_CALL;
            case "unconditional_jump" -> RefType.UNCONDITIONAL_JUMP;
            case "conditional_jump"   -> RefType.CONDITIONAL_JUMP;
            case "computed_jump"      -> RefType.COMPUTED_JUMP;
            case "fall_through"       -> RefType.FALL_THROUGH;
            case "read"               -> RefType.READ;
            case "write"              -> RefType.WRITE;
            case "read_write"         -> RefType.READ_WRITE;
            case "indirection"        -> RefType.INDIRECTION;
            default                    -> RefType.DATA;
        };
    }

    // ── /refs/create ─────────────────────────────────────────────────

    public void handleCreate(HttpExchange ex) throws IOException {
        Program prog = pa.currentProgram();
        if (prog == null) { Http.error(ex, 503, "no program loaded"); return; }
        Map<String, String> q = Http.parseQuery(ex.getRequestURI().getQuery());
        Address src = prog.getAddressFactory().getAddress(q.getOrDefault("src", ""));
        Address dst = prog.getAddressFactory().getAddress(q.getOrDefault("dst", ""));
        Integer op = parseIntegerOrNull(q.get("op_index"));
        if (src == null || dst == null) { Http.error(ex, 400, "need 'src' + 'dst'"); return; }
        RefType rt = refTypeFromName(q.get("ref_type"));
        ReferenceManager rm = prog.getReferenceManager();
        int tx = prog.startTransaction("decepticon mcp: refs/create");
        Reference r = null;
        try {
            r = rm.addMemoryReference(src, dst, rt, SourceType.USER_DEFINED, op == null ? 0 : op);
        } finally {
            prog.endTransaction(tx, true);
        }
        if (r == null) { Http.error(ex, 500, "addMemoryReference returned null"); return; }
        Http.ok(ex, Map.of(
            "src", src.toString(),
            "dst", dst.toString(),
            "type", r.getReferenceType().getName(),
            "op_index", r.getOperandIndex()
        ));
    }

    // ── /refs/delete ─────────────────────────────────────────────────

    public void handleDelete(HttpExchange ex) throws IOException {
        Program prog = pa.currentProgram();
        if (prog == null) { Http.error(ex, 503, "no program loaded"); return; }
        Map<String, String> q = Http.parseQuery(ex.getRequestURI().getQuery());
        Address src = prog.getAddressFactory().getAddress(q.getOrDefault("src", ""));
        Address dst = prog.getAddressFactory().getAddress(q.getOrDefault("dst", ""));
        Integer op = parseIntegerOrNull(q.get("op_index"));
        if (src == null || dst == null) { Http.error(ex, 400, "need 'src' + 'dst'"); return; }
        ReferenceManager rm = prog.getReferenceManager();
        Reference target = rm.getReference(src, dst, op == null ? 0 : op);
        if (target == null) { Http.error(ex, 404, "no such ref"); return; }
        int tx = prog.startTransaction("decepticon mcp: refs/delete");
        try { rm.delete(target); }
        finally { prog.endTransaction(tx, true); }
        Http.ok(ex, Map.of("src", src.toString(), "dst", dst.toString(), "deleted", true));
    }

    // ── /refs/set_primary ────────────────────────────────────────────

    public void handleSetPrimary(HttpExchange ex) throws IOException {
        Program prog = pa.currentProgram();
        if (prog == null) { Http.error(ex, 503, "no program loaded"); return; }
        Map<String, String> q = Http.parseQuery(ex.getRequestURI().getQuery());
        Address src = prog.getAddressFactory().getAddress(q.getOrDefault("src", ""));
        Address dst = prog.getAddressFactory().getAddress(q.getOrDefault("dst", ""));
        Integer op = parseIntegerOrNull(q.get("op_index"));
        boolean primary = !"false".equalsIgnoreCase(q.getOrDefault("primary", "true"));
        if (src == null || dst == null) { Http.error(ex, 400, "need 'src' + 'dst'"); return; }
        ReferenceManager rm = prog.getReferenceManager();
        Reference target = rm.getReference(src, dst, op == null ? 0 : op);
        if (target == null) { Http.error(ex, 404, "no such ref"); return; }
        int tx = prog.startTransaction("decepticon mcp: refs/set_primary");
        try { rm.setPrimary(target, primary); }
        finally { prog.endTransaction(tx, true); }
        Http.ok(ex, Map.of("src", src.toString(), "dst", dst.toString(), "primary", primary));
    }

    // ── /refs/by_type ────────────────────────────────────────────────

    public void handleByType(HttpExchange ex) throws IOException {
        Program prog = pa.currentProgram();
        if (prog == null) { Http.error(ex, 503, "no program loaded"); return; }
        Map<String, String> q = Http.parseQuery(ex.getRequestURI().getQuery());
        Address addr = prog.getAddressFactory().getAddress(q.getOrDefault("addr", ""));
        String filter = q.getOrDefault("kind", "all");  // call|jump|data|flow|all
        if (addr == null) { Http.error(ex, 400, "bad addr"); return; }
        ReferenceManager rm = prog.getReferenceManager();
        ReferenceIterator it = rm.getReferencesTo(addr);
        List<Map<String, Object>> out = new ArrayList<>();
        while (it.hasNext()) {
            Reference r = it.next();
            RefType t = r.getReferenceType();
            boolean keep = switch (filter) {
                case "call" -> t.isCall();
                case "jump" -> t.isJump();
                case "data" -> t.isData();
                case "flow" -> t instanceof FlowType;
                default      -> true;
            };
            if (keep) {
                out.add(Map.of(
                    "from", r.getFromAddress().toString(),
                    "type", t.getName(),
                    "primary", r.isPrimary()
                ));
            }
        }
        Http.ok(ex, Map.of("addr", addr.toString(), "filter", filter, "count", out.size(), "refs", out));
    }

    // ── /refs/count_to + /refs/count_from ────────────────────────────

    public void handleCountTo(HttpExchange ex) throws IOException {
        Program prog = pa.currentProgram();
        if (prog == null) { Http.error(ex, 503, "no program loaded"); return; }
        Map<String, String> q = Http.parseQuery(ex.getRequestURI().getQuery());
        Address a = prog.getAddressFactory().getAddress(q.getOrDefault("addr", ""));
        if (a == null) { Http.error(ex, 400, "bad addr"); return; }
        int n = prog.getReferenceManager().getReferenceCountTo(a);
        Http.ok(ex, Map.of("addr", a.toString(), "count", n));
    }

    public void handleCountFrom(HttpExchange ex) throws IOException {
        Program prog = pa.currentProgram();
        if (prog == null) { Http.error(ex, 503, "no program loaded"); return; }
        Map<String, String> q = Http.parseQuery(ex.getRequestURI().getQuery());
        Address a = prog.getAddressFactory().getAddress(q.getOrDefault("addr", ""));
        if (a == null) { Http.error(ex, 400, "bad addr"); return; }
        int n = prog.getReferenceManager().getReferenceCountFrom(a);
        Http.ok(ex, Map.of("addr", a.toString(), "count", n));
    }

    // ── /refs/external_only ──────────────────────────────────────────

    public void handleExternalOnly(HttpExchange ex) throws IOException {
        Program prog = pa.currentProgram();
        if (prog == null) { Http.error(ex, 503, "no program loaded"); return; }
        Map<String, String> q = Http.parseQuery(ex.getRequestURI().getQuery());
        Address a = prog.getAddressFactory().getAddress(q.getOrDefault("addr", ""));
        if (a == null) { Http.error(ex, 400, "bad addr"); return; }
        Reference[] refs = prog.getReferenceManager().getReferencesFrom(a);
        List<Map<String, Object>> out = new ArrayList<>();
        for (Reference r : refs) {
            if (!r.isExternalReference()) continue;
            out.add(Map.of(
                "from", r.getFromAddress().toString(),
                "to", r.getToAddress().toString(),
                "type", r.getReferenceType().getName()
            ));
        }
        Http.ok(ex, Map.of("addr", a.toString(), "count", out.size(), "external_refs", out));
    }

    private static Integer parseIntegerOrNull(String s) {
        if (s == null) return null;
        try { return Integer.parseInt(s); } catch (Exception e) { return null; }
    }
}
