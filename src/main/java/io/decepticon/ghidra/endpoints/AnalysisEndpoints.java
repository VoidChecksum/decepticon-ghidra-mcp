/* AnalysisEndpoints — Tier 14: analysis options + analyzer list + project meta.
 *
 *   /analysis/list_analyzers       — registered analyzers
 *   /analysis/get_options          — current Analysis options
 *   /analysis/set_option           — toggle an analysis option
 *   /analysis/run_specific         — run one analyzer
 *   /analysis/reanalyze_all        — full reanalyze
 *   /analysis/program_changes      — info about changes since last analysis
 *   /project/options               — program-level option groups
 *   /project/list_options          — list all option names
 */

package io.decepticon.ghidra.endpoints;

import com.sun.net.httpserver.HttpExchange;

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.framework.options.Options;
import ghidra.program.model.listing.Program;

import io.decepticon.ghidra.util.Http;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public final class AnalysisEndpoints {

    private final PcodeEndpoints.ProgramAccessor pa;

    public AnalysisEndpoints(PcodeEndpoints.ProgramAccessor pa) { this.pa = pa; }

    // ── /analysis/list_analyzers ─────────────────────────────────────

    public void handleListAnalyzers(HttpExchange ex) throws IOException {
        Program prog = pa.currentProgram();
        if (prog == null) { Http.error(ex, 503, "no program loaded"); return; }
        Options opts = prog.getOptions(Program.ANALYSIS_PROPERTIES);
        List<Map<String, Object>> out = new ArrayList<>();
        for (String optName : opts.getOptionNames()) {
            Object val = opts.getObject(optName, null);
            out.add(Map.of(
                "name", optName,
                "value", val == null ? "null" : val.toString(),
                "type", val == null ? "null" : val.getClass().getSimpleName()
            ));
        }
        Http.ok(ex, Map.of("count", out.size(), "analyzers", out));
    }

    // ── /analysis/get_options ────────────────────────────────────────

    public void handleGetOptions(HttpExchange ex) throws IOException {
        Program prog = pa.currentProgram();
        if (prog == null) { Http.error(ex, 503, "no program loaded"); return; }
        Map<String, String> q = Http.parseQuery(ex.getRequestURI().getQuery());
        String group = q.getOrDefault("group", Program.ANALYSIS_PROPERTIES);
        Options opts = prog.getOptions(group);
        Map<String, Object> out = new HashMap<>();
        for (String n : opts.getOptionNames()) {
            Object v = opts.getObject(n, null);
            out.put(n, v == null ? null : v.toString());
        }
        Http.ok(ex, Map.of("group", group, "count", out.size(), "options", out));
    }

    // ── /analysis/set_option ─────────────────────────────────────────

    public void handleSetOption(HttpExchange ex) throws IOException {
        Program prog = pa.currentProgram();
        if (prog == null) { Http.error(ex, 503, "no program loaded"); return; }
        Map<String, String> q = Http.parseQuery(ex.getRequestURI().getQuery());
        String group = q.getOrDefault("group", Program.ANALYSIS_PROPERTIES);
        String name = q.get("name");
        String value = q.get("value");
        if (name == null || value == null) { Http.error(ex, 400, "need 'name' + 'value'"); return; }
        Options opts = prog.getOptions(group);
        int tx = prog.startTransaction("decepticon mcp: analysis/set_option");
        boolean ok = false;
        String error = null;
        try {
            // Best-effort type coercion based on current value
            Object current = opts.getObject(name, null);
            if (current instanceof Boolean) {
                opts.setBoolean(name, Boolean.parseBoolean(value));
            } else if (current instanceof Integer) {
                opts.setInt(name, Integer.parseInt(value));
            } else if (current instanceof Long) {
                opts.setLong(name, Long.parseLong(value));
            } else if (current instanceof Double) {
                opts.setDouble(name, Double.parseDouble(value));
            } else {
                opts.setString(name, value);
            }
            ok = true;
        } catch (Exception e) {
            error = e.getClass().getSimpleName() + ": " + e.getMessage();
        } finally {
            prog.endTransaction(tx, ok);
        }
        if (!ok) { Http.error(ex, 500, error); return; }
        Http.ok(ex, Map.of("group", group, "name", name, "value", value));
    }

    // ── /analysis/reanalyze_all ──────────────────────────────────────

    public void handleReanalyzeAll(HttpExchange ex) throws IOException {
        Program prog = pa.currentProgram();
        if (prog == null) { Http.error(ex, 503, "no program loaded"); return; }
        AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(prog);
        int tx = prog.startTransaction("decepticon mcp: analysis/reanalyze_all");
        try {
            mgr.reAnalyzeAll(null);
        } finally {
            prog.endTransaction(tx, true);
        }
        Http.ok(ex, Map.of("ok", true, "note", "Re-analysis scheduled. May continue async."));
    }

    // ── /analysis/program_changes ────────────────────────────────────

    public void handleProgramChanges(HttpExchange ex) throws IOException {
        Program prog = pa.currentProgram();
        if (prog == null) { Http.error(ex, 503, "no program loaded"); return; }
        var changes = prog.getChanges();
        Http.ok(ex, Map.of(
            "has_changes", changes != null,
            "change_class", changes == null ? "(none)" : changes.getClass().getSimpleName()
        ));
    }

    // ── /project/options ─────────────────────────────────────────────

    public void handleProjectOptions(HttpExchange ex) throws IOException {
        Program prog = pa.currentProgram();
        if (prog == null) { Http.error(ex, 503, "no program loaded"); return; }
        List<String> groups = prog.getOptionsNames();
        Map<String, Integer> sizes = new HashMap<>();
        for (String g : groups) {
            sizes.put(g, prog.getOptions(g).getOptionNames().size());
        }
        Http.ok(ex, Map.of("groups", groups, "sizes", sizes));
    }

    // ── /project/list_options ────────────────────────────────────────

    public void handleListOptions(HttpExchange ex) throws IOException {
        Program prog = pa.currentProgram();
        if (prog == null) { Http.error(ex, 503, "no program loaded"); return; }
        Map<String, String> q = Http.parseQuery(ex.getRequestURI().getQuery());
        String group = q.get("group");
        if (group == null) { Http.error(ex, 400, "missing 'group'"); return; }
        Options opts = prog.getOptions(group);
        List<String> names = new ArrayList<>(opts.getOptionNames());
        Http.ok(ex, Map.of("group", group, "count", names.size(), "names", names));
    }
}
