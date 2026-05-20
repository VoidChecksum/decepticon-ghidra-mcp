/* Decepticon Ghidra MCP — Extended plugin (v0.1).
 *
 * Extends LaurieWired/GhidraMCP w/ 8 new HTTP endpoints exposing
 * Ghidra internals not surfaced by the base plugin:
 *
 *   /pcode/emit?addr=...              (T#1) HighFunction.getPcodeOps
 *   /pcode/slice_backward?addr=...&varnode=...   (T#2)
 *   /pcode/slice_forward?addr=...&varnode=...    (T#3)
 *   /bsim/query?addr=...&db=...       (T#4) BSim similarity search
 *   /bsim/signature?addr=...          (T#5) BSim signature generation
 *   /vt/correlate?src=...&dst=...     (T#6) Version Tracking correlator
 *   /script/run                       (T#7) Eval Jython/Java
 *   /emulate?addr=...                 (T#8) SLEIGH P-code emulator
 *
 * Companion Python bridge: bridge_mcp_ghidra_extended.py
 *
 * License: GPLv3 (matches Ghidra's license).
 */

package io.decepticon.ghidra;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScriptUtil;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = "DecepticonGhidraMCPExtended",
    category = "MCP",
    shortDescription = "Decepticon Ghidra MCP Extensions",
    description = "P-code, BSim, Version Tracking, Emulator, Script tools for agentic RE."
)
public class DecepticonGhidraExtendedPlugin extends Plugin {

    private static final int DEFAULT_PORT = 8081;
    private HttpServer server;

    public DecepticonGhidraExtendedPlugin(PluginTool tool) {
        super(tool);
    }

    @Override
    public void init() {
        super.init();
        try {
            startServer();
        } catch (IOException e) {
            ghidra.util.Msg.error(this, "Failed to start Decepticon MCP extended server", e);
        }
    }

    @Override
    protected void dispose() {
        if (server != null) {
            server.stop(0);
        }
        super.dispose();
    }

    private void startServer() throws IOException {
        int port = Integer.parseInt(System.getProperty("decepticon.ghidra.port",
                                                        String.valueOf(DEFAULT_PORT)));
        server = HttpServer.create(new InetSocketAddress(port), 0);

        server.createContext("/pcode/emit",            this::handlePcodeEmit);
        server.createContext("/pcode/slice_backward",  this::handleSliceBackward);
        server.createContext("/pcode/slice_forward",   this::handleSliceForward);
        server.createContext("/bsim/query",            this::handleBsimQuery);
        server.createContext("/bsim/signature",        this::handleBsimSignature);
        server.createContext("/vt/correlate",          this::handleVtCorrelate);
        server.createContext("/script/run",            this::handleScriptRun);
        server.createContext("/emulate",               this::handleEmulate);
        server.createContext("/health",                this::handleHealth);

        server.setExecutor(null);
        server.start();
        ghidra.util.Msg.info(this, "Decepticon Ghidra MCP extended server on port " + port);
    }

    // ── helpers ──────────────────────────────────────────────────

    private Program currentProgram() {
        ProgramManager pm = tool.getService(ProgramManager.class);
        return pm == null ? null : pm.getCurrentProgram();
    }

    private Map<String, String> parseQuery(String query) {
        Map<String, String> out = new HashMap<>();
        if (query == null || query.isEmpty()) return out;
        for (String pair : query.split("&")) {
            int eq = pair.indexOf('=');
            if (eq > 0) {
                out.put(pair.substring(0, eq), pair.substring(eq + 1));
            }
        }
        return out;
    }

    private void respond(HttpExchange ex, int code, String body) throws IOException {
        byte[] data = body.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().add("Content-Type", "application/json");
        ex.sendResponseHeaders(code, data.length);
        ex.getResponseBody().write(data);
        ex.getResponseBody().close();
    }

    private void respondJson(HttpExchange ex, Object obj) throws IOException {
        // Minimal JSON encoder for the small surface we ship — string lists +
        // dicts only. For complex output we'll switch to Gson in v0.2.
        respond(ex, 200, jsonOf(obj));
    }

    @SuppressWarnings("unchecked")
    private String jsonOf(Object o) {
        if (o == null) return "null";
        if (o instanceof String) return "\"" + ((String) o).replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
        if (o instanceof Number || o instanceof Boolean) return o.toString();
        if (o instanceof List) {
            StringBuilder sb = new StringBuilder("[");
            boolean first = true;
            for (Object item : (List<?>) o) {
                if (!first) sb.append(",");
                sb.append(jsonOf(item));
                first = false;
            }
            return sb.append("]").toString();
        }
        if (o instanceof Map) {
            StringBuilder sb = new StringBuilder("{");
            boolean first = true;
            for (Map.Entry<String, ?> e : ((Map<String, ?>) o).entrySet()) {
                if (!first) sb.append(",");
                sb.append("\"").append(e.getKey()).append("\":").append(jsonOf(e.getValue()));
                first = false;
            }
            return sb.append("}").toString();
        }
        return "\"" + o.toString() + "\"";
    }

    private Address parseAddr(Program prog, String s) {
        if (s == null) return null;
        return prog.getAddressFactory().getAddress(s);
    }

    // ── handlers ─────────────────────────────────────────────────

    private void handleHealth(HttpExchange ex) throws IOException {
        respond(ex, 200, "{\"ok\":true,\"version\":\"0.1\"}");
    }

    private void handlePcodeEmit(HttpExchange ex) throws IOException {
        Program prog = currentProgram();
        if (prog == null) { respond(ex, 503, "{\"error\":\"no program loaded\"}"); return; }
        Map<String, String> q = parseQuery(ex.getRequestURI().getQuery());
        Address addr = parseAddr(prog, q.get("addr"));
        if (addr == null) { respond(ex, 400, "{\"error\":\"bad addr\"}"); return; }

        Function fn = prog.getFunctionManager().getFunctionContaining(addr);
        if (fn == null) { respond(ex, 404, "{\"error\":\"no function at addr\"}"); return; }

        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(prog);
        DecompileResults res = decomp.decompileFunction(fn, 60, null);
        if (res == null || !res.decompileCompleted()) {
            respond(ex, 500, "{\"error\":\"decompile failed\"}");
            return;
        }
        HighFunction hf = res.getHighFunction();
        if (hf == null) { respond(ex, 500, "{\"error\":\"no high function\"}"); return; }

        List<Map<String, Object>> ops = new ArrayList<>();
        Iterator<PcodeOpAST> it = hf.getPcodeOps();
        int seq = 0;
        while (it.hasNext()) {
            PcodeOpAST op = it.next();
            Map<String, Object> e = new HashMap<>();
            e.put("seq", seq++);
            e.put("mnemonic", op.getMnemonic());
            e.put("seqnum", op.getSeqnum().getTarget().toString());
            List<String> inputs = new ArrayList<>();
            for (Varnode vn : op.getInputs()) inputs.add(vn.toString());
            e.put("inputs", inputs);
            e.put("output", op.getOutput() != null ? op.getOutput().toString() : null);
            ops.add(e);
        }
        respondJson(ex, Map.of("function", fn.getName(), "addr", addr.toString(), "pcode_ops", ops));
    }

    private void handleSliceBackward(HttpExchange ex) throws IOException {
        // v0.1 stub — full impl uses Varnode.getDef() walking
        // Plumbed for the next implementation pass; returns shape contract
        // so the Python bridge can dev against it.
        respond(ex, 501, "{\"error\":\"slice_backward — impl in next iteration\",\"contract\":{\"out\":\"[{op, varnode, depth}]\"}}");
    }

    private void handleSliceForward(HttpExchange ex) throws IOException {
        respond(ex, 501, "{\"error\":\"slice_forward — impl in next iteration\",\"contract\":{\"out\":\"[{op, varnode, depth}]\"}}");
    }

    private void handleBsimQuery(HttpExchange ex) throws IOException {
        // BSim API requires database URL + client setup. Stub returns the
        // contract; full impl uses ghidra.features.bsim.query.BSimClientFactory
        respond(ex, 501, "{\"error\":\"bsim_query — needs BSim DB config\",\"contract\":{\"in\":\"addr,db_url,threshold,max_results\",\"out\":\"[{exe,fn,score,addr}]\"}}");
    }

    private void handleBsimSignature(HttpExchange ex) throws IOException {
        respond(ex, 501, "{\"error\":\"bsim_signature — impl in next iteration\",\"contract\":{\"in\":\"addr\",\"out\":{\"signature\":\"base64-encoded-sig\"}}}");
    }

    private void handleVtCorrelate(HttpExchange ex) throws IOException {
        // Version Tracking API uses VTSessionDB; needs project context for
        // both binaries. Stub for now.
        respond(ex, 501, "{\"error\":\"vt_correlate — needs project paths for src+dst\",\"contract\":{\"in\":\"src,dst,correlator\",\"out\":\"[{src_fn,dst_fn,confidence}]\"}}");
    }

    private void handleScriptRun(HttpExchange ex) throws IOException {
        // GhidraScriptUtil-based eval. Need POST body w/ {language, source, args}
        // For v0.1 ship the contract; implementation in v0.1.1
        respond(ex, 501, "{\"error\":\"script_run — impl in v0.1.1\",\"contract\":{\"in\":{\"language\":\"python|java\",\"source\":\"...\"},\"out\":{\"stdout\":\"...\",\"return_value\":\"...\"}}}");
    }

    private void handleEmulate(HttpExchange ex) throws IOException {
        Program prog = currentProgram();
        if (prog == null) { respond(ex, 503, "{\"error\":\"no program loaded\"}"); return; }
        Map<String, String> q = parseQuery(ex.getRequestURI().getQuery());
        Address addr = parseAddr(prog, q.get("addr"));
        if (addr == null) { respond(ex, 400, "{\"error\":\"bad addr\"}"); return; }

        EmulatorHelper emu = new EmulatorHelper(prog);
        try {
            emu.setBreakpoint(addr);
            // v0.1 returns a basic "emulator ready" handshake.
            // Full impl: parse regs+mem from query, run, return state.
            Map<String, Object> out = new HashMap<>();
            out.put("function", addr.toString());
            out.put("ready", true);
            out.put("note", "v0.1 returns handshake only — full step+return-state in v0.1.1");
            respondJson(ex, out);
        } finally {
            emu.dispose();
        }
    }
}
