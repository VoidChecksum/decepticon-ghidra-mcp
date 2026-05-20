/* EmulateEndpoint — /emulate
 *
 * Runs SLEIGH P-code emulation over a function entry, returning the
 * final register + memory state. Supports POST JSON body for register
 * + memory pre-state setup so the caller can synthesize fuzz-harness
 * inputs.
 *
 * GET form: simple drive-by — entry addr + max_instructions + optional
 *           stop_at. No reg/mem setup.
 * POST form (application/json): full setup
 *   {
 *     "addr": "0x00401234",
 *     "max_instructions": 10000,
 *     "stop_at": "0x004012ff",
 *     "regs": {"RDI": 4096, "RSI": 16384, "RSP": 549755813888},
 *     "mem":  [{"addr": "0x1000", "data": "deadbeef"}, ...]
 *   }
 *
 * Response shape:
 *   {
 *     "function": "...",
 *     "executed_instructions": N,
 *     "stopped_at": "0x...",
 *     "stop_reason": "breakpoint" | "max_instructions" | "exception" | "halt",
 *     "final_regs": {"RAX": ..., "RDI": ..., ...},
 *     "final_mem": [{"addr": "0x...", "data": "hex..."}, ...]   # only sampled regions
 *   }
 */

package io.decepticon.ghidra.endpoints;

import com.sun.net.httpserver.HttpExchange;

import ghidra.app.emulator.EmulatorHelper;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;

import io.decepticon.ghidra.util.Http;

import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class EmulateEndpoint {

    private final PcodeEndpoints.ProgramAccessor programAccessor;

    public EmulateEndpoint(PcodeEndpoints.ProgramAccessor programAccessor) {
        this.programAccessor = programAccessor;
    }

    public void handle(HttpExchange ex) throws IOException {
        Program prog = programAccessor.currentProgram();
        if (prog == null) { Http.error(ex, 503, "no program loaded"); return; }

        Map<String, String> q = Http.parseQuery(ex.getRequestURI().getQuery());
        EmulateParams p = new EmulateParams();
        p.parseQuery(q);

        if ("POST".equalsIgnoreCase(ex.getRequestMethod())) {
            String body = Http.slurpBody(ex);
            p.parseBody(body);
        }

        if (p.addrStr == null) {
            Http.error(ex, 400, "missing 'addr'");
            return;
        }
        Address entry = prog.getAddressFactory().getAddress(p.addrStr);
        if (entry == null) {
            Http.error(ex, 400, "bad addr: " + p.addrStr);
            return;
        }
        Function fn = prog.getFunctionManager().getFunctionContaining(entry);
        String fnName = fn != null ? fn.getName() : "<no function>";

        EmulatorHelper emu = new EmulatorHelper(prog);
        Map<String, Object> result = new HashMap<>();
        result.put("function", fnName);
        result.put("entry", entry.toString());
        try {
            // Apply requested register pre-state
            for (Map.Entry<String, Long> r : p.regs.entrySet()) {
                Register reg = prog.getLanguage().getRegister(r.getKey());
                if (reg == null) continue;
                emu.writeRegister(reg, BigInteger.valueOf(r.getValue()));
            }
            // Apply requested memory pre-state
            for (MemWrite mw : p.memWrites) {
                Address ma = prog.getAddressFactory().getAddress(mw.addrStr);
                if (ma == null) continue;
                emu.writeMemory(ma, mw.data);
            }

            // Stop breakpoint
            Address stopAt = p.stopAtStr != null
                ? prog.getAddressFactory().getAddress(p.stopAtStr)
                : null;
            if (stopAt != null) {
                emu.setBreakpoint(stopAt);
            }

            // Set PC to entry. EmulatorHelper has no setExecutionAddress —
            // we write the language's program-counter register directly.
            ghidra.program.model.lang.Register pc =
                prog.getLanguage().getProgramCounter();
            if (pc != null) {
                emu.writeRegister(pc, entry.getOffset());
            }

            long executed = 0;
            String stopReason = "max_instructions";
            while (executed < p.maxInstructions) {
                boolean stepped = emu.step(ghidra.util.task.TaskMonitor.DUMMY);
                if (!stepped) {
                    stopReason = "halt";
                    break;
                }
                executed++;
                Address curr = emu.getExecutionAddress();
                if (curr == null) {
                    stopReason = "exception";
                    break;
                }
                if (stopAt != null && curr.equals(stopAt)) {
                    stopReason = "breakpoint";
                    break;
                }
            }

            result.put("executed_instructions", executed);
            result.put("stopped_at", emu.getExecutionAddress() != null
                ? emu.getExecutionAddress().toString() : "unknown");
            result.put("stop_reason", stopReason);

            // Capture final register state
            Map<String, String> finalRegs = new HashMap<>();
            for (String name : interestingRegisters(prog)) {
                Register reg = prog.getLanguage().getRegister(name);
                if (reg == null) continue;
                try {
                    BigInteger v = emu.readRegister(reg);
                    finalRegs.put(name, v != null ? "0x" + v.toString(16) : "null");
                } catch (Exception ignored) {}
            }
            result.put("final_regs", finalRegs);

            // Capture final memory state — only the regions caller wrote
            List<Map<String, String>> finalMem = new ArrayList<>();
            for (MemWrite mw : p.memWrites) {
                Address ma = prog.getAddressFactory().getAddress(mw.addrStr);
                if (ma == null) continue;
                try {
                    byte[] read = emu.readMemory(ma, mw.data.length);
                    finalMem.add(Map.of(
                        "addr", mw.addrStr,
                        "data", bytesToHex(read)
                    ));
                } catch (Exception ignored) {}
            }
            result.put("final_mem", finalMem);

            Http.ok(ex, result);
        } catch (Exception em) {
            result.put("ok", false);
            result.put("exception", em.getClass().getSimpleName() + ": " + em.getMessage());
            Http.send(ex, 500, io.decepticon.ghidra.util.Json.of(result));
        } finally {
            emu.dispose();
        }
    }

    // ── Param parsing ─────────────────────────────────────────────────

    private static class EmulateParams {
        String addrStr;
        String stopAtStr;
        long maxInstructions = 10000;
        Map<String, Long> regs = new HashMap<>();
        List<MemWrite> memWrites = new ArrayList<>();

        void parseQuery(Map<String, String> q) {
            if (q.containsKey("addr")) addrStr = q.get("addr");
            if (q.containsKey("stop_at")) stopAtStr = q.get("stop_at");
            if (q.containsKey("max_instructions")) {
                try { maxInstructions = Long.parseLong(q.get("max_instructions")); }
                catch (NumberFormatException ignored) {}
            }
        }

        void parseBody(String body) {
            // Pull top-level scalar fields
            String a = jsonStringField(body, "addr");
            if (a != null) addrStr = a;
            String s = jsonStringField(body, "stop_at");
            if (s != null) stopAtStr = s;
            String m = jsonNumberField(body, "max_instructions");
            if (m != null) {
                try { maxInstructions = Long.parseLong(m); } catch (Exception ignored) {}
            }
            // regs: { "RDI": 4096, "RSI": 16384, ... }
            String regsBlock = jsonObjectField(body, "regs");
            if (regsBlock != null) {
                Matcher rm = Pattern.compile("\"([A-Za-z][A-Za-z0-9_]*)\"\\s*:\\s*([-\\d]+|\"0x[0-9a-fA-F]+\")").matcher(regsBlock);
                while (rm.find()) {
                    String name = rm.group(1);
                    String val = rm.group(2);
                    try { regs.put(name, parseLongFlexible(val.replace("\"", ""))); }
                    catch (NumberFormatException ignored) {}
                }
            }
            // mem: [ { "addr": "0x1000", "data": "deadbeef" }, ... ]
            String memBlock = jsonArrayField(body, "mem");
            if (memBlock != null) {
                Matcher mm = Pattern.compile("\\{[^}]*\"addr\"\\s*:\\s*\"([^\"]+)\"[^}]*\"data\"\\s*:\\s*\"([0-9a-fA-F]+)\"[^}]*\\}").matcher(memBlock);
                while (mm.find()) {
                    String addr = mm.group(1);
                    String hex = mm.group(2);
                    if (hex.length() % 2 != 0) continue;
                    byte[] bytes = new byte[hex.length() / 2];
                    for (int i = 0; i < bytes.length; i++) {
                        bytes[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
                    }
                    memWrites.add(new MemWrite(addr, bytes));
                }
            }
        }
    }

    private record MemWrite(String addrStr, byte[] data) {}

    // ── Reg sampling — heuristic top-N per arch ───────────────────────

    private static List<String> interestingRegisters(Program prog) {
        // Cheap heuristic: scan the lang's register list, prefer those
        // whose name matches common general-purpose patterns.
        List<String> out = new ArrayList<>();
        for (Register r : prog.getLanguage().getRegisters()) {
            String n = r.getName();
            if (n.matches("R(A|B|C|D|S|D)X|RSP|RBP|R(8|9|1[0-5])"
                + "|E(A|B|C|D|S|D|S|B)X|ESP|EBP"
                + "|R0|R1|R2|R3|R4|R5|R6|R7|R(1[0-5])|LR|PC|SP|FP"
                + "|RIP|EIP")) {
                out.add(n);
            }
            if (out.size() >= 20) break;
        }
        if (out.isEmpty()) {
            // Fallback: first 8 registers
            int i = 0;
            for (Register r : prog.getLanguage().getRegisters()) {
                if (i++ >= 8) break;
                out.add(r.getName());
            }
        }
        return out;
    }

    // ── JSON field helpers (no Gson) ──────────────────────────────────

    private static String jsonStringField(String body, String key) {
        Matcher m = Pattern.compile("\"" + Pattern.quote(key) + "\"\\s*:\\s*\"((?:\\\\\"|[^\"])*)\"").matcher(body);
        return m.find() ? m.group(1).replace("\\\"", "\"") : null;
    }

    private static String jsonNumberField(String body, String key) {
        Matcher m = Pattern.compile("\"" + Pattern.quote(key) + "\"\\s*:\\s*([-\\d]+)").matcher(body);
        return m.find() ? m.group(1) : null;
    }

    private static String jsonObjectField(String body, String key) {
        return extractBracketedField(body, key, '{', '}');
    }

    private static String jsonArrayField(String body, String key) {
        return extractBracketedField(body, key, '[', ']');
    }

    private static String extractBracketedField(String body, String key, char open, char close) {
        String marker = "\"" + key + "\"";
        int idx = body.indexOf(marker);
        if (idx < 0) return null;
        int colon = body.indexOf(':', idx + marker.length());
        if (colon < 0) return null;
        int start = body.indexOf(open, colon);
        if (start < 0) return null;
        int depth = 1;
        for (int i = start + 1; i < body.length(); i++) {
            char c = body.charAt(i);
            if (c == open) depth++;
            else if (c == close) {
                depth--;
                if (depth == 0) return body.substring(start + 1, i);
            }
        }
        return null;
    }

    private static long parseLongFlexible(String s) {
        s = s.trim();
        if (s.startsWith("0x") || s.startsWith("0X")) {
            return Long.parseUnsignedLong(s.substring(2), 16);
        }
        return Long.parseLong(s);
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) sb.append(String.format("%02x", b & 0xff));
        return sb.toString();
    }
}
