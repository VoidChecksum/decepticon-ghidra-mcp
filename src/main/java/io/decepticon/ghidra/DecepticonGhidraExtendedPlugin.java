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
import io.decepticon.ghidra.endpoints.CallGraphEndpoints;
import io.decepticon.ghidra.endpoints.DecompilerEndpoints;
import io.decepticon.ghidra.endpoints.EmulateEndpoint;
import io.decepticon.ghidra.endpoints.PatchEndpoints;
import io.decepticon.ghidra.endpoints.PcodeEndpoints;
import io.decepticon.ghidra.endpoints.ScriptEndpoint;
import io.decepticon.ghidra.endpoints.SearchEndpoints;
import io.decepticon.ghidra.endpoints.TypeEndpoints;
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

    public static final String VERSION = "0.2.0";
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
        DecompilerEndpoints decomp = new DecompilerEndpoints(this);
        CallGraphEndpoints cg = new CallGraphEndpoints(this);
        TypeEndpoints types = new TypeEndpoints(this);
        PatchEndpoints patch = new PatchEndpoints(this);
        SearchEndpoints search = new SearchEndpoints(this);

        server.createContext("/health", this::handleHealth);
        // Tier 1 — original v0.1 surface
        server.createContext("/pcode/emit", pcode::handleEmit);
        server.createContext("/pcode/slice_backward", pcode::handleSliceBackward);
        server.createContext("/pcode/slice_forward", pcode::handleSliceForward);
        server.createContext("/bsim/signature", bsim::handleSignature);
        server.createContext("/bsim/query", bsim::handleQuery);
        server.createContext("/vt/correlate", vt::handle);
        server.createContext("/script/run", script::handle);
        server.createContext("/emulate", emulate::handle);
        // Tier 2 — decompiler quality + renaming
        server.createContext("/decompile/function", decomp::handleDecompileFunction);
        server.createContext("/decompile/quality", decomp::handleDecompileQuality);
        server.createContext("/symbols/rename_function", decomp::handleRenameFunction);
        server.createContext("/symbols/set_signature", decomp::handleSetSignature);
        server.createContext("/symbols/list_functions", decomp::handleListFunctions);
        server.createContext("/symbols/list_strings", decomp::handleListStrings);
        server.createContext("/symbols/list_symbols", decomp::handleListSymbols);
        server.createContext("/symbols/list_imports", decomp::handleListImports);
        server.createContext("/symbols/list_exports", decomp::handleListExports);
        // Tier 3 — call graph
        server.createContext("/callgraph/outgoing", cg::handleOutgoing);
        server.createContext("/callgraph/incoming", cg::handleIncoming);
        server.createContext("/callgraph/path", cg::handlePath);
        server.createContext("/callgraph/entrypoints", cg::handleEntrypoints);
        server.createContext("/callgraph/leaves", cg::handleLeaves);
        // Tier 4 — type recovery
        server.createContext("/types/list", types::handleList);
        server.createContext("/types/get_struct", types::handleGetStruct);
        server.createContext("/types/apply_struct_at", types::handleApplyStructAt);
        server.createContext("/types/recover_function", types::handleRecoverFunction);
        server.createContext("/types/list_at_addr", types::handleListAtAddr);
        // Tier 5 — patching
        server.createContext("/patch/assemble", patch::handleAssemble);
        server.createContext("/patch/nop_range", patch::handleNopRange);
        server.createContext("/patch/write_bytes", patch::handleWriteBytes);
        server.createContext("/patch/bookmark", patch::handleBookmark);
        server.createContext("/patch/list_bookmarks", patch::handleListBookmarks);
        // Tier 6 — search + memory + project
        server.createContext("/search/bytes", search::handleSearchBytes);
        server.createContext("/search/text", search::handleSearchText);
        server.createContext("/xrefs/to", search::handleXrefsTo);
        server.createContext("/xrefs/from", search::handleXrefsFrom);
        server.createContext("/memory/map", search::handleMemoryMap);
        server.createContext("/memory/read", search::handleMemoryRead);
        server.createContext("/project/info", search::handleProjectInfo);
        server.createContext("/project/analyze", search::handleAnalyze);
        server.createContext("/project/save", search::handleSave);

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
