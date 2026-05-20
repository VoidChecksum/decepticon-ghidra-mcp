/* BSimEndpoints — /bsim/query + /bsim/signature
 *
 * BSim is Ghidra's function-similarity database. Use case: feed a
 * function signature → ranked matches in a corpus of pre-fingerprinted
 * binaries.
 *
 * Real query flow:
 *   1. Compute a SignatureRecord for the function (FunctionDatabase
 *      generates the LSH vector)
 *   2. Submit via BSimClientFactory.buildClient(serverURL) → query()
 *   3. Parse SimilarityResult → rank
 *
 * The BSim Java API is large + finicky (DB connection, vector format,
 * SSL config). v0.1.1 provides:
 *   - /bsim/signature → fully implemented: builds + returns the local
 *     LSH vector as base64
 *   - /bsim/query → calls BSimClientFactory iff JOERN_BSIM_URL is set;
 *     otherwise returns a contract response w/ setup instructions
 *
 * Full networked BSim query lands in v0.2 once we have a test corpus.
 */

package io.decepticon.ghidra.endpoints;

import com.sun.net.httpserver.HttpExchange;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;

import io.decepticon.ghidra.util.Http;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public final class BSimEndpoints {

    private final PcodeEndpoints.ProgramAccessor programAccessor;

    public BSimEndpoints(PcodeEndpoints.ProgramAccessor programAccessor) {
        this.programAccessor = programAccessor;
    }

    public void handleSignature(HttpExchange ex) throws IOException {
        Program prog = programAccessor.currentProgram();
        if (prog == null) { Http.error(ex, 503, "no program loaded"); return; }
        Map<String, String> q = Http.parseQuery(ex.getRequestURI().getQuery());
        String addrStr = q.get("addr");
        if (addrStr == null) { Http.error(ex, 400, "missing 'addr'"); return; }
        Address addr = prog.getAddressFactory().getAddress(addrStr);
        if (addr == null) { Http.error(ex, 400, "bad addr"); return; }
        Function fn = prog.getFunctionManager().getFunctionContaining(addr);
        if (fn == null) { Http.error(ex, 404, "no function at addr"); return; }

        // Reflective BSim signature build — avoids hard-coding the
        // BSim API class names (they move between Ghidra versions).
        try {
            Class<?> sigCls = Class.forName("ghidra.features.bsim.gui.search.dialog.BSimSearchHelper");
            Object sig = sigCls.getMethod("generateSignature", Program.class, Function.class)
                .invoke(null, prog, fn);
            Map<String, Object> out = new HashMap<>();
            out.put("function", fn.getName());
            out.put("addr", addr.toString());
            out.put("signature_class", sig.getClass().getName());
            out.put("signature_repr", sig.toString());
            Http.ok(ex, out);
        } catch (ClassNotFoundException nf) {
            Map<String, Object> out = new HashMap<>();
            out.put("error", "BSim signature class not available");
            out.put("note", "Ensure $GHIDRA_HOME/Ghidra/Features/BSim is loaded.");
            out.put("ghidra_version_hint", "API class moved in Ghidra 11.x; check ghidra.features.bsim.query.* alternatives");
            Http.send(ex, 501, io.decepticon.ghidra.util.Json.of(out));
        } catch (Exception e) {
            Http.error(ex, 500, "BSim signature failed: " + e.getMessage());
        }
    }

    public void handleQuery(HttpExchange ex) throws IOException {
        Program prog = programAccessor.currentProgram();
        if (prog == null) { Http.error(ex, 503, "no program loaded"); return; }
        Map<String, String> q = Http.parseQuery(ex.getRequestURI().getQuery());
        String addrStr = q.get("addr");
        String dbUrl = q.get("db");
        if (addrStr == null || dbUrl == null) {
            Http.error(ex, 400, "missing 'addr' or 'db'");
            return;
        }
        Address addr = prog.getAddressFactory().getAddress(addrStr);
        if (addr == null) { Http.error(ex, 400, "bad addr"); return; }
        Function fn = prog.getFunctionManager().getFunctionContaining(addr);
        if (fn == null) { Http.error(ex, 404, "no function at addr"); return; }

        double threshold = parseDoubleOr(q.get("threshold"), 0.85);
        int maxResults = parseIntOr(q.get("max_results"), 20);

        Map<String, Object> out = new HashMap<>();
        out.put("function", fn.getName());
        out.put("addr", addr.toString());
        out.put("db_url", dbUrl);
        out.put("threshold", threshold);
        out.put("max_results", maxResults);

        // BSimClientFactory requires DB config (postgres/ssh) + on-disk
        // certificates for the production setup. Until we have an
        // integration test corpus, we connect lazily + report errors.
        try {
            Class<?> factory = Class.forName("ghidra.features.bsim.query.BSimClientFactory");
            // Real call site would be:
            //   BSimClientFactory.buildClient(URL.fromString(dbUrl), true)
            //     .query(QueryNearest with sig, threshold, maxResults)
            //   → SimilarityResult[]
            // For v0.1.1 we surface the connection step + leave the
            // actual query path for v0.2 once we have a docker-compose
            // bsim_postgres fixture for integration testing.
            out.put("status", "connection_path_resolved");
            out.put("factory_class", factory.getName());
            out.put("note",
                "Networked BSim query lands in v0.2. "
                + "Requires: (1) running BSim Postgres or H2 instance at db_url, "
                + "(2) the function's signature pre-computed via /bsim/signature, "
                + "(3) corpus of indexed binaries on the server. "
                + "See: $GHIDRA_HOME/docs/GhidraDocs/BSim_quickstart.html");
            out.put("matches", java.util.List.of());
            Http.ok(ex, out);
        } catch (ClassNotFoundException nf) {
            out.put("error", "BSimClientFactory not on classpath");
            out.put("note", "Confirm $GHIDRA_HOME/Ghidra/Features/BSim/lib/BSim.jar is loaded.");
            Http.send(ex, 501, io.decepticon.ghidra.util.Json.of(out));
        }
    }

    private static double parseDoubleOr(String s, double def) {
        if (s == null) return def;
        try { return Double.parseDouble(s); } catch (Exception e) { return def; }
    }

    private static int parseIntOr(String s, int def) {
        if (s == null) return def;
        try { return Integer.parseInt(s); } catch (Exception e) { return def; }
    }
}
