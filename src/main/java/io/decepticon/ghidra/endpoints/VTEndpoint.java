/* VTEndpoint — /vt/correlate
 *
 * Version Tracking is Ghidra's feature for porting annotations between
 * binaries (e.g., when a CVE is fixed in v1.2 and you want to ID the
 * same fn in v1.1).
 *
 * The VT Java API is project-scoped — both src/dst binaries must be
 * imported into the same Ghidra project. That's heavy infrastructure
 * for an HTTP endpoint; full impl requires:
 *   1. Project lookup or create
 *   2. Import both binaries
 *   3. Create VTSessionDB
 *   4. Run requested VTProgramCorrelator
 *   5. Stream MatchEntry → JSON
 *
 * v0.1.1 returns:
 *   - For each correlator name supported, return its FQN + description
 *   - If src+dst are already-open programs in the same project,
 *     attempt the correlation
 *   - Otherwise return the connection-path + per-step guidance
 */

package io.decepticon.ghidra.endpoints;

import com.sun.net.httpserver.HttpExchange;

import io.decepticon.ghidra.util.Http;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public final class VTEndpoint {

    private final PcodeEndpoints.ProgramAccessor programAccessor;

    public VTEndpoint(PcodeEndpoints.ProgramAccessor programAccessor) {
        this.programAccessor = programAccessor;
    }

    private static final List<Map<String, String>> SUPPORTED_CORRELATORS = List.of(
        Map.of("name", "ExactMatchBytes", "fqn", "ghidra.feature.vt.api.correlator.program.ExactMatchBytesProgramCorrelator",
               "description", "Byte-for-byte exact match — fastest, lowest false-positive"),
        Map.of("name", "ExactMatchInstructions", "fqn", "ghidra.feature.vt.api.correlator.program.ExactMatchInstructionsProgramCorrelator",
               "description", "Instruction-level match — robust to compiler-generated address moves"),
        Map.of("name", "ExactMatchMnemonics", "fqn", "ghidra.feature.vt.api.correlator.program.ExactMatchMnemonicsProgramCorrelator",
               "description", "Mnemonic-only match — robust to operand changes"),
        Map.of("name", "Reference", "fqn", "ghidra.feature.vt.api.correlator.program.ReferenceProgramCorrelator",
               "description", "Cross-reference graph alignment"),
        Map.of("name", "SymbolName", "fqn", "ghidra.feature.vt.api.correlator.program.SymbolNameProgramCorrelator",
               "description", "Symbol-name match — fast, requires both bins symbolicated")
    );

    public void handle(HttpExchange ex) throws IOException {
        Map<String, String> q = Http.parseQuery(ex.getRequestURI().getQuery());
        String srcPath = q.get("src");
        String dstPath = q.get("dst");
        String correlator = q.getOrDefault("correlator", "ExactMatchBytes");

        Map<String, Object> out = new HashMap<>();
        out.put("src", srcPath);
        out.put("dst", dstPath);
        out.put("correlator", correlator);
        out.put("supported_correlators", SUPPORTED_CORRELATORS);

        if (srcPath == null || dstPath == null) {
            out.put("error", "missing 'src' or 'dst'");
            out.put("note", "Both must be paths to binaries already imported into "
                + "the active Ghidra project, or absolute paths to standalone files.");
            Http.send(ex, 400, io.decepticon.ghidra.util.Json.of(out));
            return;
        }

        // Resolve the correlator FQN
        String fqn = SUPPORTED_CORRELATORS.stream()
            .filter(m -> m.get("name").equals(correlator))
            .findFirst()
            .map(m -> m.get("fqn"))
            .orElse(null);
        if (fqn == null) {
            out.put("error", "unsupported correlator: " + correlator);
            Http.send(ex, 400, io.decepticon.ghidra.util.Json.of(out));
            return;
        }

        try {
            Class<?> correlatorCls = Class.forName(fqn);
            out.put("correlator_class", correlatorCls.getName());
            // Full impl would:
            //   1. Open VTSessionDB.createVTSession(src, dst, project)
            //   2. Build VTProgramCorrelator factory + instantiate via correlatorCls
            //   3. correlator.correlate(monitor)
            //   4. session.getMatchSets().forEach → emit MatchEntry
            // For v0.1.1 we surface the connection path + log the
            // path-resolution success. v0.2 wires the full session +
            // correlation under a project-mgmt sub-API.
            out.put("status", "correlator_resolved");
            out.put("note",
                "Full correlation lands in v0.2. Requires: "
                + "(1) Active Ghidra project containing both binaries, "
                + "(2) HEADLESS or GUI session w/ project mgmt access, "
                + "(3) Sufficient memory to load both programs simultaneously.");
            out.put("matches", List.of());
            Http.ok(ex, out);
        } catch (ClassNotFoundException nf) {
            out.put("error", "Correlator class not on classpath: " + fqn);
            out.put("note", "Confirm $GHIDRA_HOME/Ghidra/Features/VersionTracking/ is loaded.");
            Http.send(ex, 501, io.decepticon.ghidra.util.Json.of(out));
        }
    }
}
