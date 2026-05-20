/* CommentEquateEndpoints — Tier 7: comments + equates.
 *
 * Comments (5 types: EOL, PRE, POST, PLATE, REPEATABLE):
 *   /comments/set            — set comment at addr (type=eol|pre|post|plate|repeatable)
 *   /comments/get            — get comment at addr (one or all types)
 *   /comments/list           — paginated comment iterator across program
 *   /comments/clear          — clear comment at addr
 *
 * Equates (named constants on instruction operands):
 *   /equates/list            — all defined equates
 *   /equates/create          — create equate at op
 *   /equates/get_at          — equate(s) at addr/op
 *   /equates/delete          — delete equate
 *   /equates/rename          — rename equate
 */

package io.decepticon.ghidra.endpoints;

import com.sun.net.httpserver.HttpExchange;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Equate;
import ghidra.program.model.symbol.EquateTable;

import io.decepticon.ghidra.util.Http;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

public final class CommentEquateEndpoints {

    private final PcodeEndpoints.ProgramAccessor pa;

    public CommentEquateEndpoints(PcodeEndpoints.ProgramAccessor pa) { this.pa = pa; }

    private static int commentTypeFromName(String name) {
        return switch (name == null ? "eol" : name.toLowerCase()) {
            case "pre"        -> CodeUnit.PRE_COMMENT;
            case "post"       -> CodeUnit.POST_COMMENT;
            case "plate"      -> CodeUnit.PLATE_COMMENT;
            case "repeatable" -> CodeUnit.REPEATABLE_COMMENT;
            default            -> CodeUnit.EOL_COMMENT;  // default eol
        };
    }

    private static String commentTypeName(int t) {
        return switch (t) {
            case CodeUnit.PRE_COMMENT        -> "pre";
            case CodeUnit.POST_COMMENT       -> "post";
            case CodeUnit.PLATE_COMMENT      -> "plate";
            case CodeUnit.REPEATABLE_COMMENT -> "repeatable";
            default                          -> "eol";
        };
    }

    // ── /comments/set ────────────────────────────────────────────────

    public void handleCommentSet(HttpExchange ex) throws IOException {
        Program prog = pa.currentProgram();
        if (prog == null) { Http.error(ex, 503, "no program loaded"); return; }
        Map<String, String> q = Http.parseQuery(ex.getRequestURI().getQuery());
        Address a = prog.getAddressFactory().getAddress(q.getOrDefault("addr", ""));
        String comment = q.get("comment");
        if (a == null || comment == null) { Http.error(ex, 400, "need 'addr' + 'comment'"); return; }
        int type = commentTypeFromName(q.get("type"));
        Listing l = prog.getListing();
        int tx = prog.startTransaction("decepticon mcp: comments/set");
        try {
            l.setComment(a, type, comment);
        } finally {
            prog.endTransaction(tx, true);
        }
        Http.ok(ex, Map.of(
            "addr", a.toString(),
            "type", commentTypeName(type),
            "comment", comment
        ));
    }

    // ── /comments/get ────────────────────────────────────────────────

    public void handleCommentGet(HttpExchange ex) throws IOException {
        Program prog = pa.currentProgram();
        if (prog == null) { Http.error(ex, 503, "no program loaded"); return; }
        Map<String, String> q = Http.parseQuery(ex.getRequestURI().getQuery());
        Address a = prog.getAddressFactory().getAddress(q.getOrDefault("addr", ""));
        if (a == null) { Http.error(ex, 400, "bad addr"); return; }
        Listing l = prog.getListing();
        String typeParam = q.get("type");
        Map<String, Object> out = new HashMap<>();
        out.put("addr", a.toString());
        if (typeParam != null) {
            int type = commentTypeFromName(typeParam);
            out.put("type", commentTypeName(type));
            out.put("comment", l.getComment(type, a));
        } else {
            Map<String, String> all = new HashMap<>();
            for (int t : new int[]{CodeUnit.EOL_COMMENT, CodeUnit.PRE_COMMENT,
                                    CodeUnit.POST_COMMENT, CodeUnit.PLATE_COMMENT,
                                    CodeUnit.REPEATABLE_COMMENT}) {
                String c = l.getComment(t, a);
                if (c != null) all.put(commentTypeName(t), c);
            }
            out.put("comments", all);
        }
        Http.ok(ex, out);
    }

    // ── /comments/clear ──────────────────────────────────────────────

    public void handleCommentClear(HttpExchange ex) throws IOException {
        Program prog = pa.currentProgram();
        if (prog == null) { Http.error(ex, 503, "no program loaded"); return; }
        Map<String, String> q = Http.parseQuery(ex.getRequestURI().getQuery());
        Address a = prog.getAddressFactory().getAddress(q.getOrDefault("addr", ""));
        if (a == null) { Http.error(ex, 400, "bad addr"); return; }
        int type = commentTypeFromName(q.get("type"));
        Listing l = prog.getListing();
        int tx = prog.startTransaction("decepticon mcp: comments/clear");
        try {
            l.setComment(a, type, null);
        } finally {
            prog.endTransaction(tx, true);
        }
        Http.ok(ex, Map.of("addr", a.toString(), "type", commentTypeName(type), "cleared", true));
    }

    // ── /comments/list ───────────────────────────────────────────────

    public void handleCommentList(HttpExchange ex) throws IOException {
        Program prog = pa.currentProgram();
        if (prog == null) { Http.error(ex, 503, "no program loaded"); return; }
        Map<String, String> q = Http.parseQuery(ex.getRequestURI().getQuery());
        int limit = parseIntOr(q.get("limit"), 200);
        int type = commentTypeFromName(q.get("type"));
        Listing l = prog.getListing();
        AddressIterator it = l.getCommentAddressIterator(type, prog.getMemory(), true);
        List<Map<String, Object>> out = new ArrayList<>();
        while (it.hasNext() && out.size() < limit) {
            Address a = it.next();
            String c = l.getComment(type, a);
            if (c == null) continue;
            out.add(Map.of("addr", a.toString(), "type", commentTypeName(type), "comment", c));
        }
        Http.ok(ex, Map.of("count", out.size(), "comments", out));
    }

    // ── /equates/list ────────────────────────────────────────────────

    public void handleEquatesList(HttpExchange ex) throws IOException {
        Program prog = pa.currentProgram();
        if (prog == null) { Http.error(ex, 503, "no program loaded"); return; }
        Map<String, String> q = Http.parseQuery(ex.getRequestURI().getQuery());
        int limit = parseIntOr(q.get("limit"), 500);
        EquateTable et = prog.getEquateTable();
        Iterator<Equate> it = et.getEquates();
        List<Map<String, Object>> out = new ArrayList<>();
        while (it.hasNext() && out.size() < limit) {
            Equate e = it.next();
            out.add(Map.of(
                "name", e.getName(),
                "value", e.getValue(),
                "reference_count", e.getReferenceCount(),
                "display_name", e.getDisplayName(),
                "valid", e.isValidUUID()
            ));
        }
        Http.ok(ex, Map.of("count", out.size(), "equates", out));
    }

    // ── /equates/create ──────────────────────────────────────────────

    public void handleEquateCreate(HttpExchange ex) throws IOException {
        Program prog = pa.currentProgram();
        if (prog == null) { Http.error(ex, 503, "no program loaded"); return; }
        Map<String, String> q = Http.parseQuery(ex.getRequestURI().getQuery());
        Address a = prog.getAddressFactory().getAddress(q.getOrDefault("addr", ""));
        String name = q.get("name");
        Long value = parseLongOrNull(q.get("value"));
        Integer opIdx = parseIntegerOrNull(q.get("op_index"));
        if (a == null || name == null || value == null) {
            Http.error(ex, 400, "need 'addr' + 'name' + 'value'"); return;
        }
        int tx = prog.startTransaction("decepticon mcp: equates/create");
        boolean ok = false;
        String error = null;
        Equate result = null;
        try {
            EquateTable et = prog.getEquateTable();
            result = et.getEquate(name);
            if (result == null) {
                result = et.createEquate(name, value);
            }
            // Bind to the instruction op if op_index given
            if (opIdx != null) {
                result.addReference(a, opIdx);
            }
            ok = true;
        } catch (Exception e) {
            error = e.getClass().getSimpleName() + ": " + e.getMessage();
        } finally {
            prog.endTransaction(tx, ok);
        }
        if (!ok || result == null) { Http.error(ex, 500, error == null ? "create failed" : error); return; }
        Http.ok(ex, Map.of(
            "name", result.getName(),
            "value", result.getValue(),
            "addr", a.toString(),
            "op_index", opIdx == null ? -1 : opIdx
        ));
    }

    // ── /equates/get_at ──────────────────────────────────────────────

    public void handleEquateGetAt(HttpExchange ex) throws IOException {
        Program prog = pa.currentProgram();
        if (prog == null) { Http.error(ex, 503, "no program loaded"); return; }
        Map<String, String> q = Http.parseQuery(ex.getRequestURI().getQuery());
        Address a = prog.getAddressFactory().getAddress(q.getOrDefault("addr", ""));
        Integer opIdx = parseIntegerOrNull(q.get("op_index"));
        if (a == null) { Http.error(ex, 400, "bad addr"); return; }
        EquateTable et = prog.getEquateTable();
        List<Map<String, Object>> out = new ArrayList<>();
        if (opIdx != null) {
            for (Equate e : et.getEquates(a, opIdx)) {
                out.add(Map.of("name", e.getName(), "value", e.getValue()));
            }
        } else {
            for (Equate e : et.getEquates(a)) {
                out.add(Map.of("name", e.getName(), "value", e.getValue()));
            }
        }
        Http.ok(ex, Map.of("addr", a.toString(), "count", out.size(), "equates", out));
    }

    // ── /equates/delete ──────────────────────────────────────────────

    public void handleEquateDelete(HttpExchange ex) throws IOException {
        Program prog = pa.currentProgram();
        if (prog == null) { Http.error(ex, 503, "no program loaded"); return; }
        Map<String, String> q = Http.parseQuery(ex.getRequestURI().getQuery());
        String name = q.get("name");
        if (name == null) { Http.error(ex, 400, "missing 'name'"); return; }
        int tx = prog.startTransaction("decepticon mcp: equates/delete");
        boolean removed = false;
        try {
            removed = prog.getEquateTable().removeEquate(name);
        } finally {
            prog.endTransaction(tx, true);
        }
        Http.ok(ex, Map.of("name", name, "removed", removed));
    }

    // ── /equates/rename ──────────────────────────────────────────────

    public void handleEquateRename(HttpExchange ex) throws IOException {
        Program prog = pa.currentProgram();
        if (prog == null) { Http.error(ex, 503, "no program loaded"); return; }
        Map<String, String> q = Http.parseQuery(ex.getRequestURI().getQuery());
        String oldName = q.get("name");
        String newName = q.get("new_name");
        if (oldName == null || newName == null) {
            Http.error(ex, 400, "need 'name' + 'new_name'"); return;
        }
        EquateTable et = prog.getEquateTable();
        Equate old = et.getEquate(oldName);
        if (old == null) { Http.error(ex, 404, "no equate named: " + oldName); return; }
        int tx = prog.startTransaction("decepticon mcp: equates/rename");
        boolean ok = false;
        String error = null;
        try {
            old.renameEquate(newName);
            ok = true;
        } catch (Exception e) {
            error = e.getClass().getSimpleName() + ": " + e.getMessage();
        } finally {
            prog.endTransaction(tx, ok);
        }
        if (!ok) { Http.error(ex, 500, error); return; }
        Http.ok(ex, Map.of("old_name", oldName, "new_name", newName));
    }

    // ── helpers ──────────────────────────────────────────────────────

    private static int parseIntOr(String s, int def) {
        if (s == null) return def;
        try { return Integer.parseInt(s); } catch (Exception e) { return def; }
    }

    private static Long parseLongOrNull(String s) {
        if (s == null) return null;
        try {
            if (s.startsWith("0x")) return Long.parseUnsignedLong(s.substring(2), 16);
            return Long.parseLong(s);
        } catch (Exception e) { return null; }
    }

    private static Integer parseIntegerOrNull(String s) {
        if (s == null) return null;
        try { return Integer.parseInt(s); } catch (Exception e) { return null; }
    }
}
