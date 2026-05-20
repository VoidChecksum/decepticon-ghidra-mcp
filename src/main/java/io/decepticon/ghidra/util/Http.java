/* Http — HTTP helpers for endpoint handlers.
 *
 * Centralizes query-string parsing, body slurping, and response
 * writing so handler classes stay focused on Ghidra logic.
 */

package io.decepticon.ghidra.util;

import com.sun.net.httpserver.HttpExchange;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

public final class Http {

    private Http() {}

    public static Map<String, String> parseQuery(String query) {
        Map<String, String> out = new HashMap<>();
        if (query == null || query.isEmpty()) return out;
        for (String pair : query.split("&")) {
            int eq = pair.indexOf('=');
            if (eq < 0) continue;
            String k = URLDecoder.decode(pair.substring(0, eq), StandardCharsets.UTF_8);
            String v = URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8);
            out.put(k, v);
        }
        return out;
    }

    public static String slurpBody(HttpExchange ex) throws IOException {
        try (InputStream is = ex.getRequestBody()) {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            byte[] buf = new byte[4096];
            int n;
            while ((n = is.read(buf)) > 0) {
                baos.write(buf, 0, n);
            }
            return baos.toString(StandardCharsets.UTF_8);
        }
    }

    public static void send(HttpExchange ex, int code, String body) throws IOException {
        byte[] data = body.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().add("Content-Type", "application/json");
        ex.sendResponseHeaders(code, data.length);
        ex.getResponseBody().write(data);
        ex.getResponseBody().close();
    }

    public static void ok(HttpExchange ex, Object obj) throws IOException {
        send(ex, 200, Json.of(obj));
    }

    public static void error(HttpExchange ex, int code, String message) throws IOException {
        send(ex, code, Json.error(message));
    }

    public static String requiredQueryParam(Map<String, String> q, String key) {
        String v = q.get(key);
        if (v == null || v.isEmpty()) {
            throw new IllegalArgumentException("missing required query parameter: " + key);
        }
        return v;
    }

    public static long parseHexOrDecimal(String s) {
        s = s.trim();
        if (s.startsWith("0x") || s.startsWith("0X")) {
            return Long.parseUnsignedLong(s.substring(2), 16);
        }
        return Long.parseLong(s);
    }
}
