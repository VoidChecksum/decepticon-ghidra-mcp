/* CallGraphEndpoints — Tier 3 (call-graph navigation).
 *
 *   /callgraph/outgoing      — callees of a function
 *   /callgraph/incoming      — callers of a function
 *   /callgraph/path          — find shortest path src→dst (BFS)
 *   /callgraph/entrypoints   — program entry points
 *   /callgraph/leaves        — functions that call nothing further
 *   /callgraph/sinks         — functions that are called but call nothing
 */

package io.decepticon.ghidra.endpoints;

import com.sun.net.httpserver.HttpExchange;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;

import io.decepticon.ghidra.util.Http;

import java.io.IOException;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public final class CallGraphEndpoints {

    private final PcodeEndpoints.ProgramAccessor programAccessor;

    public CallGraphEndpoints(PcodeEndpoints.ProgramAccessor pa) {
        this.programAccessor = pa;
    }

    // ── /callgraph/outgoing ──────────────────────────────────────────

    public void handleOutgoing(HttpExchange ex) throws IOException {
        Program prog = programAccessor.currentProgram();
        if (prog == null) { Http.error(ex, 503, "no program loaded"); return; }
        Map<String, String> q = Http.parseQuery(ex.getRequestURI().getQuery());
        Address a = prog.getAddressFactory().getAddress(q.getOrDefault("addr", ""));
        if (a == null) { Http.error(ex, 400, "bad addr"); return; }
        Function fn = prog.getFunctionManager().getFunctionContaining(a);
        if (fn == null) { Http.error(ex, 404, "no function at addr"); return; }

        Set<Function> callees = fn.getCalledFunctions(ghidra.util.task.TaskMonitor.DUMMY);
        List<Map<String, Object>> out = new ArrayList<>();
        for (Function c : callees) {
            out.add(Map.of(
                "name", c.getName(),
                "addr", c.getEntryPoint().toString(),
                "external", c.isExternal(),
                "thunk", c.isThunk()
            ));
        }
        Http.ok(ex, Map.of(
            "function", fn.getName(),
            "addr", fn.getEntryPoint().toString(),
            "count", out.size(),
            "callees", out
        ));
    }

    // ── /callgraph/incoming ──────────────────────────────────────────

    public void handleIncoming(HttpExchange ex) throws IOException {
        Program prog = programAccessor.currentProgram();
        if (prog == null) { Http.error(ex, 503, "no program loaded"); return; }
        Map<String, String> q = Http.parseQuery(ex.getRequestURI().getQuery());
        Address a = prog.getAddressFactory().getAddress(q.getOrDefault("addr", ""));
        if (a == null) { Http.error(ex, 400, "bad addr"); return; }
        Function fn = prog.getFunctionManager().getFunctionContaining(a);
        if (fn == null) { Http.error(ex, 404, "no function at addr"); return; }

        Set<Function> callers = fn.getCallingFunctions(ghidra.util.task.TaskMonitor.DUMMY);
        List<Map<String, Object>> out = new ArrayList<>();
        for (Function c : callers) {
            out.add(Map.of(
                "name", c.getName(),
                "addr", c.getEntryPoint().toString()
            ));
        }
        Http.ok(ex, Map.of(
            "function", fn.getName(),
            "count", out.size(),
            "callers", out
        ));
    }

    // ── /callgraph/path ──────────────────────────────────────────────

    public void handlePath(HttpExchange ex) throws IOException {
        Program prog = programAccessor.currentProgram();
        if (prog == null) { Http.error(ex, 503, "no program loaded"); return; }
        Map<String, String> q = Http.parseQuery(ex.getRequestURI().getQuery());
        Address srcA = prog.getAddressFactory().getAddress(q.getOrDefault("src", ""));
        Address dstA = prog.getAddressFactory().getAddress(q.getOrDefault("dst", ""));
        if (srcA == null || dstA == null) {
            Http.error(ex, 400, "need 'src' + 'dst' addresses");
            return;
        }
        Function src = prog.getFunctionManager().getFunctionContaining(srcA);
        Function dst = prog.getFunctionManager().getFunctionContaining(dstA);
        if (src == null || dst == null) {
            Http.error(ex, 404, "src or dst not at a function");
            return;
        }
        int maxDepth = parseIntOr(q.get("max_depth"), 10);

        // BFS over call edges
        Map<Function, Function> parent = new HashMap<>();
        Set<Function> visited = new HashSet<>();
        Deque<FunDepth> work = new ArrayDeque<>();
        work.add(new FunDepth(src, 0));
        visited.add(src);
        Function reached = null;
        while (!work.isEmpty()) {
            FunDepth fd = work.poll();
            if (fd.fn.equals(dst)) { reached = fd.fn; break; }
            if (fd.depth >= maxDepth) continue;
            for (Function callee : fd.fn.getCalledFunctions(ghidra.util.task.TaskMonitor.DUMMY)) {
                if (!visited.add(callee)) continue;
                parent.put(callee, fd.fn);
                work.add(new FunDepth(callee, fd.depth + 1));
            }
        }
        if (reached == null) {
            Http.ok(ex, Map.of(
                "src", src.getName(),
                "dst", dst.getName(),
                "reachable", false,
                "max_depth", maxDepth
            ));
            return;
        }
        // Reconstruct path
        List<Map<String, String>> path = new ArrayList<>();
        Function cur = reached;
        Deque<Function> stack = new ArrayDeque<>();
        while (cur != null) {
            stack.push(cur);
            cur = parent.get(cur);
        }
        while (!stack.isEmpty()) {
            Function f = stack.pop();
            path.add(Map.of(
                "name", f.getName(),
                "addr", f.getEntryPoint().toString()
            ));
        }
        Http.ok(ex, Map.of(
            "src", src.getName(),
            "dst", dst.getName(),
            "reachable", true,
            "path_length", path.size(),
            "path", path
        ));
    }

    // ── /callgraph/entrypoints ───────────────────────────────────────

    public void handleEntrypoints(HttpExchange ex) throws IOException {
        Program prog = programAccessor.currentProgram();
        if (prog == null) { Http.error(ex, 503, "no program loaded"); return; }
        List<Map<String, Object>> out = new ArrayList<>();
        var iter = prog.getSymbolTable().getExternalEntryPointIterator();
        while (iter.hasNext()) {
            Address a = iter.next();
            Function fn = prog.getFunctionManager().getFunctionContaining(a);
            out.add(Map.of(
                "addr", a.toString(),
                "function", fn != null ? fn.getName() : "(none)",
                "is_function", fn != null
            ));
        }
        // Plus the program-level entry point
        if (prog.getImageBase() != null) {
            Address entry = prog.getImageBase();
            // No reliable single-entry API; rely on entry-point iterator.
        }
        Http.ok(ex, Map.of("count", out.size(), "entrypoints", out));
    }

    // ── /callgraph/leaves ────────────────────────────────────────────

    public void handleLeaves(HttpExchange ex) throws IOException {
        Program prog = programAccessor.currentProgram();
        if (prog == null) { Http.error(ex, 503, "no program loaded"); return; }
        Map<String, String> q = Http.parseQuery(ex.getRequestURI().getQuery());
        int limit = parseIntOr(q.get("limit"), 500);
        List<Map<String, Object>> out = new ArrayList<>();
        var it = prog.getFunctionManager().getFunctions(true);
        while (it.hasNext() && out.size() < limit) {
            Function fn = it.next();
            if (fn.isExternal() || fn.isThunk()) continue;
            if (fn.getCalledFunctions(ghidra.util.task.TaskMonitor.DUMMY).isEmpty()) {
                out.add(Map.of(
                    "name", fn.getName(),
                    "addr", fn.getEntryPoint().toString()
                ));
            }
        }
        Http.ok(ex, Map.of("count", out.size(), "leaves", out));
    }

    // ── helpers ──────────────────────────────────────────────────────

    private record FunDepth(Function fn, int depth) {}

    private static int parseIntOr(String s, int def) {
        if (s == null) return def;
        try { return Integer.parseInt(s); } catch (Exception e) { return def; }
    }

    @SuppressWarnings("unused")
    private static Reference unusedRef(ReferenceManager rm, Address a) {
        // Reserved API for v0.2.1 — reference-based call edges across thunks
        ReferenceIterator it = rm.getReferencesTo(a);
        return it.hasNext() ? it.next() : null;
    }
}
