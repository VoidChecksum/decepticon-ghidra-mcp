/* Decepticon Ghidra MCP — Extended plugin v0.1.1.
 *
 * HTTP-fronted Ghidra introspection. Endpoints exposed:
 *
 *   /pcode/emit              — HighFunction.getPcodeOps (T#1)
 *   /pcode/slice_backward    — Varnode.getDef() ancestor walk (T#2)
 *   /pcode/slice_forward     — Varnode.getDescendants walk (T#3)
 *   /bsim/query              — BSim similarity search (T#4)
 *   /bsim/signature          — BSim signature emit (T#5)
 *   /vt/correlate            — Version Tracking correlator (T#6)
 *   /script/run              — Jython/Java eval (T#7)
 *   /emulate                 — SLEIGH P-code emulator full run (T#8)
 *
 * v0.1.1 changes from v0.1:
 *   - All 6 stubs filled in (pcode slicing, script_run, full emulate,
 *     bsim signature + query scaffolding, vt correlate scaffolding)
 *   - Handlers split into endpoints/ classes for maintainability
 *   - JSON encoding centralized in util/Json
 *   - HTTP helpers centralized in util/Http
 *
 * Companion Python bridge: scripts/bridge_mcp_ghidra_extended.py
 * License: GPLv3
 */

package io.decepticon.ghidra;

import com.sun.net.httpserver.HttpServer;

import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;

import io.decepticon.ghidra.endpoints.BSimEndpoints;
import io.decepticon.ghidra.endpoints.EmulateEndpoint;
import io.decepticon.ghidra.endpoints.PcodeEndpoints;
import io.decepticon.ghidra.endpoints.ScriptEndpoint;
import io.decepticon.ghidra.endpoints.VTEndpoint;
import io.decepticon.ghidra.util.Http;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.Map;

@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = "DecepticonGhidraMCPExtended",
    category = "MCP",
    shortDescription = "Decepticon Ghidra MCP Extensions",
    description = "P-code, BSim, Version Tracking, Emulator, Script tools for agentic RE."
)
public class DecepticonGhidraExtendedPlugin extends Plugin
        implements PcodeEndpoints.ProgramAccessor {

    public static final String VERSION = "0.1.1";
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

    @Override
    public Program currentProgram() {
        ProgramManager pm = tool.getService(ProgramManager.class);
        return pm == null ? null : pm.getCurrentProgram();
    }

    private void startServer() throws IOException {
        int port = Integer.parseInt(System.getProperty(
            "decepticon.ghidra.port", String.valueOf(DEFAULT_PORT)));

        server = HttpServer.create(new InetSocketAddress(port), 0);

        // Endpoint instances share `this` as the ProgramAccessor so
        // they always read the currently-active program.
        PcodeEndpoints pcode = new PcodeEndpoints(this);
        BSimEndpoints bsim = new BSimEndpoints(this);
        VTEndpoint vt = new VTEndpoint(this);
        ScriptEndpoint script = new ScriptEndpoint(this);
        EmulateEndpoint emulate = new EmulateEndpoint(this);

        server.createContext("/health", this::handleHealth);
        server.createContext("/pcode/emit", pcode::handleEmit);
        server.createContext("/pcode/slice_backward", pcode::handleSliceBackward);
        server.createContext("/pcode/slice_forward", pcode::handleSliceForward);
        server.createContext("/bsim/signature", bsim::handleSignature);
        server.createContext("/bsim/query", bsim::handleQuery);
        server.createContext("/vt/correlate", vt::handle);
        server.createContext("/script/run", script::handle);
        server.createContext("/emulate", emulate::handle);

        server.setExecutor(null);
        server.start();
        ghidra.util.Msg.info(this,
            "Decepticon Ghidra MCP extended server v" + VERSION
            + " listening on port " + port);
    }

    private void handleHealth(com.sun.net.httpserver.HttpExchange ex) throws IOException {
        Program prog = currentProgram();
        Http.ok(ex, Map.of(
            "ok", true,
            "version", VERSION,
            "program_loaded", prog != null,
            "program_name", prog != null ? prog.getName() : null
        ));
    }
}
