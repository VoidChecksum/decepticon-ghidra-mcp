/* ScriptEndpoint — /script/run
 *
 * Evaluates Jython source (or Java for future) in the Ghidra script
 * context. Backed by a Jython ScriptEngine — Ghidra ships Jython 2.7
 * embedded; we use the same classpath to avoid spinning up a separate
 * interpreter.
 *
 * The script's stdout/stderr are captured and returned in the JSON
 * response. ``currentProgram`` is pre-bound to the active program so
 * scripts can do ``currentProgram.getFunctionManager().getFunctions(True)``
 * etc.
 *
 * Body shape (POST application/json):
 *     {"language": "python", "source": "...", "args": ["..."]}
 *
 * Security: Ghidra plugin runs as the operator. Scripts have full
 * access to the program + filesystem. This endpoint is intentionally
 * unrestricted — that's the point.
 */

package io.decepticon.ghidra.endpoints;

import com.sun.net.httpserver.HttpExchange;

import ghidra.program.model.listing.Program;

import io.decepticon.ghidra.util.Http;

import javax.script.ScriptContext;
import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import javax.script.ScriptException;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class ScriptEndpoint {

    private final PcodeEndpoints.ProgramAccessor programAccessor;
    private final ScriptEngineManager engineManager;

    public ScriptEndpoint(PcodeEndpoints.ProgramAccessor programAccessor) {
        this.programAccessor = programAccessor;
        this.engineManager = new ScriptEngineManager();
    }

    public void handle(HttpExchange ex) throws IOException {
        if (!"POST".equalsIgnoreCase(ex.getRequestMethod())) {
            Http.error(ex, 405, "use POST with JSON body");
            return;
        }
        String body = Http.slurpBody(ex);
        String language = extractStringField(body, "language");
        String source = extractStringField(body, "source");
        List<String> args = extractStringList(body, "args");
        if (language == null) language = "python";
        if (source == null) {
            Http.error(ex, 400, "missing 'source' in JSON body");
            return;
        }

        ScriptEngine engine = pickEngine(language);
        if (engine == null) {
            Http.error(ex, 501, "no script engine available for language: " + language
                + ". For Jython, set GHIDRA_HOME and ensure Jython is on the plugin classpath.");
            return;
        }

        Program prog = programAccessor.currentProgram();
        engine.put("currentProgram", prog);
        engine.put("args", args);

        // Capture stdout / stderr
        StringWriter stdout = new StringWriter();
        StringWriter stderr = new StringWriter();
        engine.getContext().setWriter(new PrintWriter(stdout));
        engine.getContext().setErrorWriter(new PrintWriter(stderr));

        Map<String, Object> result = new HashMap<>();
        result.put("language", language);
        long start = System.currentTimeMillis();
        try {
            Object retVal = engine.eval(source);
            result.put("ok", true);
            result.put("return_value", retVal == null ? null : retVal.toString());
        } catch (ScriptException sex) {
            result.put("ok", false);
            result.put("exception", sex.getMessage());
        } catch (Exception other) {
            result.put("ok", false);
            result.put("exception", other.getClass().getSimpleName() + ": " + other.getMessage());
        }
        result.put("stdout", stdout.toString());
        result.put("stderr", stderr.toString());
        result.put("elapsed_ms", System.currentTimeMillis() - start);
        Http.ok(ex, result);
    }

    private ScriptEngine pickEngine(String language) {
        // Ghidra ships Jython 2.7; ScriptEngineManager finds it via SPI.
        // Try the language name and the standard aliases.
        String[] aliases = switch (language.toLowerCase()) {
            case "python", "jython" -> new String[]{"jython", "python"};
            case "java", "groovy" -> new String[]{"groovy", language};
            default -> new String[]{language};
        };
        for (String a : aliases) {
            ScriptEngine e = engineManager.getEngineByName(a);
            if (e != null) return e;
        }
        return null;
    }

    // ── Minimal JSON field extraction — body is small + simple ────────

    private static final Pattern STRING_FIELD =
        Pattern.compile("\"([^\"]+)\"\\s*:\\s*\"((?:\\\\\"|[^\"])*)\"");

    private static String extractStringField(String body, String key) {
        Matcher m = STRING_FIELD.matcher(body);
        while (m.find()) {
            if (key.equals(m.group(1))) {
                return unescape(m.group(2));
            }
        }
        return null;
    }

    private static List<String> extractStringList(String body, String key) {
        // Match key followed by [ ... ]
        Pattern p = Pattern.compile("\"" + Pattern.quote(key) + "\"\\s*:\\s*\\[([^\\]]*)\\]");
        Matcher m = p.matcher(body);
        if (!m.find()) return List.of();
        String inner = m.group(1);
        List<String> out = new java.util.ArrayList<>();
        Matcher sm = Pattern.compile("\"((?:\\\\\"|[^\"])*)\"").matcher(inner);
        while (sm.find()) {
            out.add(unescape(sm.group(1)));
        }
        return out;
    }

    private static String unescape(String s) {
        return s.replace("\\\"", "\"").replace("\\\\", "\\").replace("\\n", "\n").replace("\\t", "\t");
    }
}
