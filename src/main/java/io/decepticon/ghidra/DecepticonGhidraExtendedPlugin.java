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

import io.decepticon.ghidra.endpoints.AnalysisEndpoints;
import io.decepticon.ghidra.endpoints.BSimEndpoints;
import io.decepticon.ghidra.endpoints.CallGraphEndpoints;
import io.decepticon.ghidra.endpoints.CommentEquateEndpoints;
import io.decepticon.ghidra.endpoints.DataTypeAdvancedEndpoints;
import io.decepticon.ghidra.endpoints.DecompilerEndpoints;
import io.decepticon.ghidra.endpoints.EmulateEndpoint;
import io.decepticon.ghidra.endpoints.FunctionAdvancedEndpoints;
import io.decepticon.ghidra.endpoints.ListingEndpoints;
import io.decepticon.ghidra.endpoints.MemoryBlockEndpoints;
import io.decepticon.ghidra.endpoints.PatchEndpoints;
import io.decepticon.ghidra.endpoints.PcodeEndpoints;
import io.decepticon.ghidra.endpoints.ReferenceCrudEndpoints;
import io.decepticon.ghidra.endpoints.ScriptEndpoint;
import io.decepticon.ghidra.endpoints.SearchEndpoints;
import io.decepticon.ghidra.endpoints.SymbolEndpoints;
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

    public static final String VERSION = "0.3.0";
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
        CommentEquateEndpoints commentEquate = new CommentEquateEndpoints(this);
        SymbolEndpoints sym = new SymbolEndpoints(this);
        DataTypeAdvancedEndpoints typesAdv = new DataTypeAdvancedEndpoints(this);
        FunctionAdvancedEndpoints fnAdv = new FunctionAdvancedEndpoints(this);
        ReferenceCrudEndpoints refCrud = new ReferenceCrudEndpoints(this);
        MemoryBlockEndpoints memBlocks = new MemoryBlockEndpoints(this);
        ListingEndpoints listing = new ListingEndpoints(this);
        AnalysisEndpoints analysis = new AnalysisEndpoints(this);

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
        // Tier 7 — Comments + Equates
        server.createContext("/comments/set",   commentEquate::handleCommentSet);
        server.createContext("/comments/get",   commentEquate::handleCommentGet);
        server.createContext("/comments/clear", commentEquate::handleCommentClear);
        server.createContext("/comments/list",  commentEquate::handleCommentList);
        server.createContext("/equates/list",   commentEquate::handleEquatesList);
        server.createContext("/equates/create", commentEquate::handleEquateCreate);
        server.createContext("/equates/get_at", commentEquate::handleEquateGetAt);
        server.createContext("/equates/delete", commentEquate::handleEquateDelete);
        server.createContext("/equates/rename", commentEquate::handleEquateRename);
        // Tier 8 — Symbols deep
        server.createContext("/symbols/create_label",        sym::handleCreateLabel);
        server.createContext("/symbols/delete",              sym::handleDelete);
        server.createContext("/symbols/get_at_addr",         sym::handleGetAtAddr);
        server.createContext("/symbols/get_by_name",         sym::handleGetByName);
        server.createContext("/symbols/set_primary",         sym::handleSetPrimary);
        server.createContext("/symbols/list_namespaces",     sym::handleListNamespaces);
        server.createContext("/symbols/create_namespace",    sym::handleCreateNamespace);
        server.createContext("/symbols/create_class",        sym::handleCreateClass);
        server.createContext("/symbols/list_class_symbols",  sym::handleListClassSymbols);
        server.createContext("/symbols/get_label_history",   sym::handleGetLabelHistory);
        // Tier 9 — Data types advanced
        server.createContext("/types/create_struct",      typesAdv::handleCreateStruct);
        server.createContext("/types/add_struct_field",   typesAdv::handleAddStructField);
        server.createContext("/types/create_union",       typesAdv::handleCreateUnion);
        server.createContext("/types/create_enum",        typesAdv::handleCreateEnum);
        server.createContext("/types/add_enum_entry",     typesAdv::handleAddEnumEntry);
        server.createContext("/types/create_typedef",     typesAdv::handleCreateTypedef);
        server.createContext("/types/create_pointer",     typesAdv::handleCreatePointer);
        server.createContext("/types/create_array",       typesAdv::handleCreateArray);
        server.createContext("/types/list_categories",    typesAdv::handleListCategories);
        server.createContext("/types/create_category",    typesAdv::handleCreateCategory);
        server.createContext("/types/find_by_name",       typesAdv::handleFindByName);
        server.createContext("/types/delete",             typesAdv::handleDelete);
        // Tier 10 — Functions deep
        server.createContext("/functions/create",            fnAdv::handleCreate);
        server.createContext("/functions/delete",            fnAdv::handleDelete);
        server.createContext("/functions/set_return_type",   fnAdv::handleSetReturnType);
        server.createContext("/functions/list_parameters",   fnAdv::handleListParameters);
        server.createContext("/functions/set_parameter",     fnAdv::handleSetParameter);
        server.createContext("/functions/list_locals",       fnAdv::handleListLocals);
        server.createContext("/functions/set_local",         fnAdv::handleSetLocal);
        server.createContext("/functions/add_tag",           fnAdv::handleAddTag);
        server.createContext("/functions/remove_tag",        fnAdv::handleRemoveTag);
        server.createContext("/functions/list_calling_conv", fnAdv::handleListCallingConv);
        server.createContext("/functions/set_calling_conv",  fnAdv::handleSetCallingConv);
        server.createContext("/functions/set_attrs",         fnAdv::handleSetAttrs);
        // Tier 11 — References CRUD
        server.createContext("/refs/create",        refCrud::handleCreate);
        server.createContext("/refs/delete",        refCrud::handleDelete);
        server.createContext("/refs/set_primary",   refCrud::handleSetPrimary);
        server.createContext("/refs/by_type",       refCrud::handleByType);
        server.createContext("/refs/count_to",      refCrud::handleCountTo);
        server.createContext("/refs/count_from",    refCrud::handleCountFrom);
        server.createContext("/refs/external_only", refCrud::handleExternalOnly);
        // Tier 12 — Memory blocks
        server.createContext("/memblocks/create_initialized",   memBlocks::handleCreateInitialized);
        server.createContext("/memblocks/create_uninitialized", memBlocks::handleCreateUninitialized);
        server.createContext("/memblocks/delete",               memBlocks::handleDelete);
        server.createContext("/memblocks/rename",               memBlocks::handleRename);
        server.createContext("/memblocks/set_permissions",      memBlocks::handleSetPermissions);
        server.createContext("/memblocks/split",                memBlocks::handleSplit);
        server.createContext("/memblocks/fill",                 memBlocks::handleFill);
        server.createContext("/memblocks/info",                 memBlocks::handleInfo);
        // Tier 13 — Listing + CodeUnits
        server.createContext("/listing/instructions",         listing::handleInstructions);
        server.createContext("/listing/get_instruction_at",   listing::handleGetInstructionAt);
        server.createContext("/listing/get_data_at",          listing::handleGetDataAt);
        server.createContext("/listing/create_instruction",   listing::handleCreateInstruction);
        server.createContext("/listing/create_data",          listing::handleCreateData);
        server.createContext("/listing/clear",                listing::handleClear);
        server.createContext("/listing/disassemble_range",    listing::handleDisassembleRange);
        server.createContext("/listing/get_string_at",        listing::handleGetStringAt);
        server.createContext("/listing/set_fallthrough",      listing::handleSetFallthrough);
        // Tier 14 — Analysis
        server.createContext("/analysis/list_analyzers",   analysis::handleListAnalyzers);
        server.createContext("/analysis/get_options",      analysis::handleGetOptions);
        server.createContext("/analysis/set_option",       analysis::handleSetOption);
        server.createContext("/analysis/reanalyze_all",    analysis::handleReanalyzeAll);
        server.createContext("/analysis/program_changes",  analysis::handleProgramChanges);
        server.createContext("/project/options",           analysis::handleProjectOptions);
        server.createContext("/project/list_options",      analysis::handleListOptions);

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
