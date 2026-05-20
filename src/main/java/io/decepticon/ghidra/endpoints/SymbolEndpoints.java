/* SymbolEndpoints — Tier 8: symbols + namespaces deep.
 *
 *   /symbols/create_label              — add a label at addr
 *   /symbols/delete                    — delete a symbol
 *   /symbols/get_at_addr               — all symbols at addr
 *   /symbols/get_by_name               — symbol lookup by name
 *   /symbols/set_primary               — promote symbol to primary
 *   /symbols/list_namespaces           — all namespaces (Class/Library/etc)
 *   /symbols/create_namespace          — new namespace
 *   /symbols/create_class              — new Class namespace
 *   /symbols/list_class_symbols        — Class-kind symbols
 *   /symbols/get_label_history         — label history at addr
 */

package io.decepticon.ghidra.endpoints;

import com.sun.net.httpserver.HttpExchange;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.LabelHistory;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;

import io.decepticon.ghidra.util.Http;

import java.util.Iterator;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public final class SymbolEndpoints {

    private final PcodeEndpoints.ProgramAccessor pa;

    public SymbolEndpoints(PcodeEndpoints.ProgramAccessor pa) { this.pa = pa; }

    // ── /symbols/create_label ────────────────────────────────────────

    public void handleCreateLabel(HttpExchange ex) throws IOException {
        Program prog = pa.currentProgram();
        if (prog == null) { Http.error(ex, 503, "no program loaded"); return; }
        Map<String, String> q = Http.parseQuery(ex.getRequestURI().getQuery());
        Address a = prog.getAddressFactory().getAddress(q.getOrDefault("addr", ""));
        String name = q.get("name");
        if (a == null || name == null) { Http.error(ex, 400, "need 'addr' + 'name'"); return; }
        SymbolTable st = prog.getSymbolTable();
        int tx = prog.startTransaction("decepticon mcp: symbols/create_label");
        boolean ok = false;
        String error = null;
        Symbol s = null;
        try {
            s = st.createLabel(a, name, SourceType.USER_DEFINED);
            ok = true;
        } catch (Exception e) {
            error = e.getClass().getSimpleName() + ": " + e.getMessage();
        } finally {
            prog.endTransaction(tx, ok);
        }
        if (!ok || s == null) { Http.error(ex, 500, error == null ? "create failed" : error); return; }
        Http.ok(ex, Map.of(
            "name", s.getName(),
            "addr", a.toString(),
            "symbol_id", s.getID(),
            "kind", s.getSymbolType().toString()
        ));
    }

    // ── /symbols/delete ──────────────────────────────────────────────

    public void handleDelete(HttpExchange ex) throws IOException {
        Program prog = pa.currentProgram();
        if (prog == null) { Http.error(ex, 503, "no program loaded"); return; }
        Map<String, String> q = Http.parseQuery(ex.getRequestURI().getQuery());
        Address a = prog.getAddressFactory().getAddress(q.getOrDefault("addr", ""));
        String name = q.get("name");
        if (a == null || name == null) { Http.error(ex, 400, "need 'addr' + 'name'"); return; }
        SymbolTable st = prog.getSymbolTable();
        Symbol s = null;
        for (Symbol cand : st.getSymbols(a)) {
            if (cand.getName().equals(name)) { s = cand; break; }
        }
        if (s == null) { Http.error(ex, 404, "no symbol named " + name + " at " + a); return; }
        int tx = prog.startTransaction("decepticon mcp: symbols/delete");
        boolean removed = false;
        try {
            removed = s.delete();
        } finally {
            prog.endTransaction(tx, true);
        }
        Http.ok(ex, Map.of("name", name, "addr", a.toString(), "removed", removed));
    }

    // ── /symbols/get_at_addr ─────────────────────────────────────────

    public void handleGetAtAddr(HttpExchange ex) throws IOException {
        Program prog = pa.currentProgram();
        if (prog == null) { Http.error(ex, 503, "no program loaded"); return; }
        Map<String, String> q = Http.parseQuery(ex.getRequestURI().getQuery());
        Address a = prog.getAddressFactory().getAddress(q.getOrDefault("addr", ""));
        if (a == null) { Http.error(ex, 400, "bad addr"); return; }
        SymbolTable st = prog.getSymbolTable();
        List<Map<String, Object>> out = new ArrayList<>();
        for (Symbol s : st.getSymbols(a)) {
            out.add(Map.of(
                "name", s.getName(),
                "kind", s.getSymbolType().toString(),
                "primary", s.isPrimary(),
                "namespace", s.getParentNamespace().getName(true),
                "id", s.getID(),
                "source", s.getSource().toString()
            ));
        }
        Http.ok(ex, Map.of("addr", a.toString(), "count", out.size(), "symbols", out));
    }

    // ── /symbols/get_by_name ─────────────────────────────────────────

    public void handleGetByName(HttpExchange ex) throws IOException {
        Program prog = pa.currentProgram();
        if (prog == null) { Http.error(ex, 503, "no program loaded"); return; }
        Map<String, String> q = Http.parseQuery(ex.getRequestURI().getQuery());
        String name = q.get("name");
        if (name == null) { Http.error(ex, 400, "missing 'name'"); return; }
        SymbolTable st = prog.getSymbolTable();
        SymbolIterator it = st.getSymbols(name);
        List<Map<String, Object>> out = new ArrayList<>();
        while (it.hasNext()) {
            Symbol s = it.next();
            out.add(Map.of(
                "name", s.getName(),
                "addr", s.getAddress().toString(),
                "kind", s.getSymbolType().toString(),
                "namespace", s.getParentNamespace().getName(true)
            ));
        }
        Http.ok(ex, Map.of("name", name, "count", out.size(), "symbols", out));
    }

    // ── /symbols/set_primary ─────────────────────────────────────────

    public void handleSetPrimary(HttpExchange ex) throws IOException {
        Program prog = pa.currentProgram();
        if (prog == null) { Http.error(ex, 503, "no program loaded"); return; }
        Map<String, String> q = Http.parseQuery(ex.getRequestURI().getQuery());
        Address a = prog.getAddressFactory().getAddress(q.getOrDefault("addr", ""));
        String name = q.get("name");
        if (a == null || name == null) { Http.error(ex, 400, "need 'addr' + 'name'"); return; }
        Symbol target = null;
        for (Symbol cand : prog.getSymbolTable().getSymbols(a)) {
            if (cand.getName().equals(name)) { target = cand; break; }
        }
        if (target == null) { Http.error(ex, 404, "no symbol " + name + " at " + a); return; }
        int tx = prog.startTransaction("decepticon mcp: symbols/set_primary");
        boolean ok = false;
        try {
            ok = target.setPrimary();
        } finally {
            prog.endTransaction(tx, ok);
        }
        Http.ok(ex, Map.of("name", name, "addr", a.toString(), "now_primary", ok));
    }

    // ── /symbols/list_namespaces ─────────────────────────────────────

    public void handleListNamespaces(HttpExchange ex) throws IOException {
        Program prog = pa.currentProgram();
        if (prog == null) { Http.error(ex, 503, "no program loaded"); return; }
        Map<String, String> q = Http.parseQuery(ex.getRequestURI().getQuery());
        int limit = parseIntOr(q.get("limit"), 200);
        // Walk symbols filtering by NAMESPACE / CLASS / LIBRARY kind
        SymbolTable st = prog.getSymbolTable();
        SymbolIterator it = st.getDefinedSymbols();
        List<Map<String, Object>> out = new ArrayList<>();
        while (it.hasNext() && out.size() < limit) {
            Symbol s = it.next();
            SymbolType k = s.getSymbolType();
            if (k != SymbolType.NAMESPACE && k != SymbolType.CLASS && k != SymbolType.LIBRARY) continue;
            out.add(Map.of(
                "name", s.getName(true),
                "kind", k.toString(),
                "id", s.getID(),
                "parent", s.getParentNamespace().getName(true)
            ));
        }
        Http.ok(ex, Map.of("count", out.size(), "namespaces", out));
    }

    // ── /symbols/create_namespace ────────────────────────────────────

    public void handleCreateNamespace(HttpExchange ex) throws IOException {
        Program prog = pa.currentProgram();
        if (prog == null) { Http.error(ex, 503, "no program loaded"); return; }
        Map<String, String> q = Http.parseQuery(ex.getRequestURI().getQuery());
        String name = q.get("name");
        String parentName = q.get("parent");  // optional full name path
        if (name == null) { Http.error(ex, 400, "missing 'name'"); return; }
        SymbolTable st = prog.getSymbolTable();
        Namespace parent = prog.getGlobalNamespace();
        if (parentName != null) {
            Namespace lookup = lookupNamespace(prog, parentName);
            if (lookup != null) parent = lookup;
        }
        int tx = prog.startTransaction("decepticon mcp: symbols/create_namespace");
        boolean ok = false;
        String error = null;
        Namespace ns = null;
        try {
            ns = st.createNameSpace(parent, name, SourceType.USER_DEFINED);
            ok = true;
        } catch (Exception e) {
            error = e.getClass().getSimpleName() + ": " + e.getMessage();
        } finally {
            prog.endTransaction(tx, ok);
        }
        if (!ok || ns == null) { Http.error(ex, 500, error == null ? "create failed" : error); return; }
        Http.ok(ex, Map.of(
            "name", ns.getName(true),
            "id", ns.getID(),
            "parent", parent.getName(true)
        ));
    }

    // ── /symbols/create_class ────────────────────────────────────────

    public void handleCreateClass(HttpExchange ex) throws IOException {
        Program prog = pa.currentProgram();
        if (prog == null) { Http.error(ex, 503, "no program loaded"); return; }
        Map<String, String> q = Http.parseQuery(ex.getRequestURI().getQuery());
        String name = q.get("name");
        if (name == null) { Http.error(ex, 400, "missing 'name'"); return; }
        SymbolTable st = prog.getSymbolTable();
        int tx = prog.startTransaction("decepticon mcp: symbols/create_class");
        boolean ok = false;
        String error = null;
        GhidraClass cls = null;
        try {
            cls = st.createClass(prog.getGlobalNamespace(), name, SourceType.USER_DEFINED);
            ok = true;
        } catch (Exception e) {
            error = e.getClass().getSimpleName() + ": " + e.getMessage();
        } finally {
            prog.endTransaction(tx, ok);
        }
        if (!ok || cls == null) { Http.error(ex, 500, error == null ? "create failed" : error); return; }
        Http.ok(ex, Map.of("name", cls.getName(true), "id", cls.getID()));
    }

    // ── /symbols/list_class_symbols ──────────────────────────────────

    public void handleListClassSymbols(HttpExchange ex) throws IOException {
        Program prog = pa.currentProgram();
        if (prog == null) { Http.error(ex, 503, "no program loaded"); return; }
        Map<String, String> q = Http.parseQuery(ex.getRequestURI().getQuery());
        int limit = parseIntOr(q.get("limit"), 500);
        SymbolTable st = prog.getSymbolTable();
        Iterator<GhidraClass> it = st.getClassNamespaces();
        List<Map<String, Object>> out = new ArrayList<>();
        while (it.hasNext() && out.size() < limit) {
            GhidraClass c = it.next();
            out.add(Map.of(
                "name", c.getName(true),
                "id", c.getID()
            ));
        }
        Http.ok(ex, Map.of("count", out.size(), "classes", out));
    }

    // ── /symbols/get_label_history ───────────────────────────────────

    public void handleGetLabelHistory(HttpExchange ex) throws IOException {
        Program prog = pa.currentProgram();
        if (prog == null) { Http.error(ex, 503, "no program loaded"); return; }
        Map<String, String> q = Http.parseQuery(ex.getRequestURI().getQuery());
        Address a = prog.getAddressFactory().getAddress(q.getOrDefault("addr", ""));
        if (a == null) { Http.error(ex, 400, "bad addr"); return; }
        LabelHistory[] hist = prog.getSymbolTable().getLabelHistory(a);
        List<Map<String, Object>> out = new ArrayList<>();
        for (LabelHistory h : hist) {
            out.add(Map.of(
                "action", h.getActionID(),
                "label", h.getLabelString(),
                "user", h.getUserName(),
                "modification_date", h.getModificationDate().toString()
            ));
        }
        Http.ok(ex, Map.of("addr", a.toString(), "count", out.size(), "history", out));
    }

    // ── helpers ──────────────────────────────────────────────────────

    private static Namespace lookupNamespace(Program prog, String fullName) {
        // Walk by colon-separated path
        Namespace current = prog.getGlobalNamespace();
        if (fullName.equals("Global") || fullName.isEmpty()) return current;
        for (String part : fullName.split("::")) {
            if (part.equals("Global")) continue;
            Namespace next = prog.getSymbolTable().getNamespace(part, current);
            if (next == null) return null;
            current = next;
        }
        return current;
    }

    private static int parseIntOr(String s, int def) {
        if (s == null) return def;
        try { return Integer.parseInt(s); } catch (Exception e) { return def; }
    }
}
