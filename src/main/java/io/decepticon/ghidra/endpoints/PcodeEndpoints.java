/* PcodeEndpoints — P-code emit + backward + forward slicing.
 *
 * P-code is Ghidra's architecture-independent IR. The HighFunction
 * obtained from DecompInterface holds the decompile-grade P-code ops
 * with SSA-form Varnodes — the right level for taint-style analysis.
 *
 * /pcode/emit            — all PcodeOpAST in a function
 * /pcode/slice_backward  — Varnode.getDef() ancestor walk
 * /pcode/slice_forward   — Varnode.getDescendants() walk
 */

package io.decepticon.ghidra.endpoints;

import com.sun.net.httpserver.HttpExchange;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;

import io.decepticon.ghidra.util.Http;
import io.decepticon.ghidra.util.Json;

import java.io.IOException;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

public final class PcodeEndpoints {

    private final ProgramAccessor programAccessor;

    public PcodeEndpoints(ProgramAccessor programAccessor) {
        this.programAccessor = programAccessor;
    }

    /** Functional callback supplied by the plugin so handlers can read the current program. */
    public interface ProgramAccessor {
        Program currentProgram();
    }

    // ── /pcode/emit ───────────────────────────────────────────────────

    public void handleEmit(HttpExchange ex) throws IOException {
        Program prog = programAccessor.currentProgram();
        if (prog == null) {
            Http.error(ex, 503, "no program loaded");
            return;
        }
        Map<String, String> q = Http.parseQuery(ex.getRequestURI().getQuery());
        String addrStr = q.get("addr");
        if (addrStr == null) {
            Http.error(ex, 400, "missing 'addr' query parameter");
            return;
        }
        Address addr = prog.getAddressFactory().getAddress(addrStr);
        if (addr == null) {
            Http.error(ex, 400, "bad addr: " + addrStr);
            return;
        }
        Function fn = prog.getFunctionManager().getFunctionContaining(addr);
        if (fn == null) {
            Http.error(ex, 404, "no function at addr");
            return;
        }
        HighFunction hf = decompile(prog, fn);
        if (hf == null) {
            Http.error(ex, 500, "decompile failed");
            return;
        }
        List<Map<String, Object>> ops = new ArrayList<>();
        Iterator<PcodeOpAST> it = hf.getPcodeOps();
        int seq = 0;
        while (it.hasNext()) {
            PcodeOpAST op = it.next();
            ops.add(opToMap(op, seq++));
        }
        Http.ok(ex, Map.of(
            "function", fn.getName(),
            "addr", addr.toString(),
            "op_count", ops.size(),
            "pcode_ops", ops
        ));
    }

    // ── /pcode/slice_backward ─────────────────────────────────────────

    public void handleSliceBackward(HttpExchange ex) throws IOException {
        Program prog = programAccessor.currentProgram();
        if (prog == null) { Http.error(ex, 503, "no program loaded"); return; }
        Map<String, String> q = Http.parseQuery(ex.getRequestURI().getQuery());
        SliceParams p = parseSliceParams(prog, q);
        if (p.error != null) { Http.error(ex, 400, p.error); return; }
        Function fn = prog.getFunctionManager().getFunctionContaining(p.addr);
        if (fn == null) { Http.error(ex, 404, "no function at addr"); return; }
        HighFunction hf = decompile(prog, fn);
        if (hf == null) { Http.error(ex, 500, "decompile failed"); return; }

        PcodeOpAST targetOp = findOpAt(hf, p.addr, p.varnodeId);
        if (targetOp == null) {
            Http.error(ex, 404, "no PcodeOp at addr with varnode index " + p.varnodeId);
            return;
        }

        // Determine the seed varnode: if varnodeId < inputs.length we slice
        // from that input; if equal we slice from the output.
        Varnode seed;
        if (p.varnodeId < targetOp.getNumInputs()) {
            seed = targetOp.getInput(p.varnodeId);
        } else {
            seed = targetOp.getOutput();
        }
        if (seed == null) {
            Http.error(ex, 400, "varnode index out of range");
            return;
        }

        List<Map<String, Object>> chain = new ArrayList<>();
        Set<Object> visited = new HashSet<>();
        Deque<SliceFrame> work = new ArrayDeque<>();
        work.push(new SliceFrame(seed, 0));
        while (!work.isEmpty()) {
            SliceFrame frame = work.pop();
            if (frame.depth > p.maxDepth) continue;
            Varnode vn = frame.vn;
            if (vn == null) continue;
            if (!visited.add(vn)) continue;
            PcodeOp def = vn.getDef();
            if (def == null) {
                // Leaf — input parameter, constant, or live-in
                chain.add(leafMap(vn, frame.depth));
                continue;
            }
            chain.add(opStepMap(def, vn, frame.depth));
            for (int i = 0; i < def.getNumInputs(); i++) {
                work.push(new SliceFrame(def.getInput(i), frame.depth + 1));
            }
        }
        Http.ok(ex, Map.of(
            "function", fn.getName(),
            "addr", p.addr.toString(),
            "seed_varnode_index", p.varnodeId,
            "direction", "backward",
            "chain", chain
        ));
    }

    // ── /pcode/slice_forward ──────────────────────────────────────────

    public void handleSliceForward(HttpExchange ex) throws IOException {
        Program prog = programAccessor.currentProgram();
        if (prog == null) { Http.error(ex, 503, "no program loaded"); return; }
        Map<String, String> q = Http.parseQuery(ex.getRequestURI().getQuery());
        SliceParams p = parseSliceParams(prog, q);
        if (p.error != null) { Http.error(ex, 400, p.error); return; }
        Function fn = prog.getFunctionManager().getFunctionContaining(p.addr);
        if (fn == null) { Http.error(ex, 404, "no function at addr"); return; }
        HighFunction hf = decompile(prog, fn);
        if (hf == null) { Http.error(ex, 500, "decompile failed"); return; }

        PcodeOpAST targetOp = findOpAt(hf, p.addr, p.varnodeId);
        if (targetOp == null) {
            Http.error(ex, 404, "no PcodeOp at addr with varnode index " + p.varnodeId);
            return;
        }
        Varnode seed;
        if (p.varnodeId < targetOp.getNumInputs()) {
            seed = targetOp.getInput(p.varnodeId);
        } else {
            seed = targetOp.getOutput();
        }
        if (seed == null) {
            Http.error(ex, 400, "varnode index out of range");
            return;
        }

        List<Map<String, Object>> chain = new ArrayList<>();
        Set<Object> visited = new HashSet<>();
        Deque<SliceFrame> work = new ArrayDeque<>();
        work.push(new SliceFrame(seed, 0));
        while (!work.isEmpty()) {
            SliceFrame frame = work.pop();
            if (frame.depth > p.maxDepth) continue;
            Varnode vn = frame.vn;
            if (vn == null) continue;
            if (!visited.add(vn)) continue;
            Iterator<PcodeOp> descIt = vn.getDescendants();
            boolean any = false;
            while (descIt.hasNext()) {
                PcodeOp use = descIt.next();
                any = true;
                chain.add(opStepMap(use, vn, frame.depth));
                Varnode out = use.getOutput();
                if (out != null) {
                    work.push(new SliceFrame(out, frame.depth + 1));
                }
            }
            if (!any) {
                // Sink — varnode has no descendants in this function's HF
                chain.add(leafMap(vn, frame.depth));
            }
        }
        Http.ok(ex, Map.of(
            "function", fn.getName(),
            "addr", p.addr.toString(),
            "seed_varnode_index", p.varnodeId,
            "direction", "forward",
            "chain", chain
        ));
    }

    // ── Helpers ────────────────────────────────────────────────────────

    private record SliceFrame(Varnode vn, int depth) {}

    private static class SliceParams {
        Address addr;
        int varnodeId;
        int maxDepth;
        String error;
    }

    private static SliceParams parseSliceParams(Program prog, Map<String, String> q) {
        SliceParams p = new SliceParams();
        String addrStr = q.get("addr");
        if (addrStr == null) { p.error = "missing 'addr'"; return p; }
        p.addr = prog.getAddressFactory().getAddress(addrStr);
        if (p.addr == null) { p.error = "bad addr: " + addrStr; return p; }
        try {
            p.varnodeId = Integer.parseInt(q.getOrDefault("varnode", "0"));
        } catch (NumberFormatException e) {
            p.error = "bad varnode index";
            return p;
        }
        try {
            p.maxDepth = Integer.parseInt(q.getOrDefault("max_depth", "20"));
        } catch (NumberFormatException e) {
            p.maxDepth = 20;
        }
        if (p.maxDepth > 200) p.maxDepth = 200;  // safety cap
        return p;
    }

    private static HighFunction decompile(Program prog, Function fn) {
        DecompInterface decomp = new DecompInterface();
        try {
            decomp.openProgram(prog);
            DecompileResults res = decomp.decompileFunction(fn, 60, null);
            if (res == null || !res.decompileCompleted()) return null;
            return res.getHighFunction();
        } finally {
            decomp.dispose();
        }
    }

    private static PcodeOpAST findOpAt(HighFunction hf, Address addr, int varnodeIdx) {
        Iterator<PcodeOpAST> it = hf.getPcodeOps(addr);
        if (!it.hasNext()) return null;
        // varnode index lets the caller pick which op at this address —
        // for multi-op instructions there can be several. Use index 0
        // by default; otherwise return the Nth.
        int n = Math.max(0, varnodeIdx);
        PcodeOpAST last = null;
        while (it.hasNext() && n >= 0) {
            last = it.next();
            n--;
        }
        return last;
    }

    private static Map<String, Object> opToMap(PcodeOpAST op, int seq) {
        Map<String, Object> e = new HashMap<>();
        e.put("seq", seq);
        e.put("mnemonic", op.getMnemonic());
        e.put("seqnum", op.getSeqnum().getTarget().toString());
        List<String> inputs = new ArrayList<>();
        for (Varnode vn : op.getInputs()) inputs.add(varnodeStr(vn));
        e.put("inputs", inputs);
        e.put("output", op.getOutput() != null ? varnodeStr(op.getOutput()) : null);
        return e;
    }

    private static Map<String, Object> opStepMap(PcodeOp op, Varnode vn, int depth) {
        Map<String, Object> e = new HashMap<>();
        e.put("depth", depth);
        e.put("op_mnemonic", op.getMnemonic());
        e.put("op_seq", op.getSeqnum().getTarget().toString());
        e.put("varnode", varnodeStr(vn));
        List<String> inputs = new ArrayList<>();
        for (Varnode v : op.getInputs()) inputs.add(varnodeStr(v));
        e.put("op_inputs", inputs);
        e.put("op_output", op.getOutput() != null ? varnodeStr(op.getOutput()) : null);
        return e;
    }

    private static Map<String, Object> leafMap(Varnode vn, int depth) {
        Map<String, Object> e = new HashMap<>();
        e.put("depth", depth);
        e.put("op_mnemonic", "LEAF");
        e.put("varnode", varnodeStr(vn));
        e.put("kind", classifyLeaf(vn));
        return e;
    }

    private static String classifyLeaf(Varnode vn) {
        if (vn.isConstant()) return "CONSTANT";
        if (vn.isInput()) return "PARAM";
        if (vn.isRegister()) return "REGISTER";
        if (vn.isAddress()) return "MEMORY";
        if (vn.isUnique()) return "TEMP";
        return "UNKNOWN";
    }

    private static String varnodeStr(Varnode vn) {
        if (vn == null) return "null";
        return String.format("%s:0x%x:%d", vn.isAddress() || vn.isRegister() ? "addr" : "vn",
                              vn.getOffset(), vn.getSize());
    }

    @SuppressWarnings("unused")
    private static String unusedJsonHelper(Object o) {
        return Json.of(o);
    }
}
