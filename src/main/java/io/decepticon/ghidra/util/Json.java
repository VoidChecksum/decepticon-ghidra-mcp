/* Json — minimal JSON encoder for the plugin's HTTP responses.
 *
 * We deliberately don't pull in Gson/Jackson — Ghidra plugins should
 * avoid extra classpath bloat. Our output shapes are simple enough
 * (strings, numbers, booleans, lists, maps) that a hand-rolled encoder
 * suffices, and we control the inputs.
 */

package io.decepticon.ghidra.util;

import java.util.Collection;
import java.util.Map;

public final class Json {

    private Json() {}

    @SuppressWarnings("unchecked")
    public static String of(Object o) {
        if (o == null) return "null";
        if (o instanceof String s) return quote(s);
        if (o instanceof Number || o instanceof Boolean) return o.toString();
        if (o instanceof Collection<?> c) {
            StringBuilder sb = new StringBuilder("[");
            boolean first = true;
            for (Object item : c) {
                if (!first) sb.append(",");
                sb.append(of(item));
                first = false;
            }
            return sb.append("]").toString();
        }
        if (o.getClass().isArray()) {
            StringBuilder sb = new StringBuilder("[");
            int len = java.lang.reflect.Array.getLength(o);
            for (int i = 0; i < len; i++) {
                if (i > 0) sb.append(",");
                sb.append(of(java.lang.reflect.Array.get(o, i)));
            }
            return sb.append("]").toString();
        }
        if (o instanceof Map<?, ?> m) {
            StringBuilder sb = new StringBuilder("{");
            boolean first = true;
            for (Map.Entry<?, ?> e : m.entrySet()) {
                if (!first) sb.append(",");
                sb.append(quote(String.valueOf(e.getKey()))).append(":").append(of(e.getValue()));
                first = false;
            }
            return sb.append("}").toString();
        }
        return quote(o.toString());
    }

    public static String error(String message) {
        return "{\"error\":" + quote(message) + "}";
    }

    public static String error(String message, Map<String, ?> context) {
        return "{\"error\":" + quote(message) + ",\"context\":" + of(context) + "}";
    }

    private static String quote(String s) {
        StringBuilder sb = new StringBuilder(s.length() + 2);
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '\\' -> sb.append("\\\\");
                case '"'  -> sb.append("\\\"");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                case '\b' -> sb.append("\\b");
                case '\f' -> sb.append("\\f");
                default -> {
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        sb.append('"');
        return sb.toString();
    }
}
