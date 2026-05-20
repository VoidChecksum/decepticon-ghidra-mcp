/* MemoryBlockEndpoints — Tier 12: memory block CRUD.
 *
 *   /memblocks/create_initialized       — new initialized block w/ size + fill
 *   /memblocks/create_uninitialized     — new uninit block (BSS-like)
 *   /memblocks/delete                   — remove block by name
 *   /memblocks/rename                   — rename block
 *   /memblocks/set_permissions          — R/W/X flags
 *   /memblocks/split                    — split at addr
 *   /memblocks/join                     — join two adjacent blocks
 *   /memblocks/fill                     — fill block region w/ value
 *   /memblocks/info                     — single-block info
 *   /memblocks/create_byte_mapped       — mapped overlay block
 */

package io.decepticon.ghidra.endpoints;

import com.sun.net.httpserver.HttpExchange;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryConflictException;

import io.decepticon.ghidra.util.Http;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public final class MemoryBlockEndpoints {

    private final PcodeEndpoints.ProgramAccessor pa;

    public MemoryBlockEndpoints(PcodeEndpoints.ProgramAccessor pa) { this.pa = pa; }

    // ── /memblocks/create_initialized ────────────────────────────────

    public void handleCreateInitialized(HttpExchange ex) throws IOException {
        Program prog = pa.currentProgram();
        if (prog == null) { Http.error(ex, 503, "no program loaded"); return; }
        Map<String, String> q = Http.parseQuery(ex.getRequestURI().getQuery());
        String name = q.get("name");
        Address start = prog.getAddressFactory().getAddress(q.getOrDefault("start", ""));
        Long size = parseLongOrNull(q.get("size"));
        Byte fill = (byte) (parseIntOr(q.get("fill"), 0) & 0xff);
        if (name == null || start == null || size == null || size <= 0) {
            Http.error(ex, 400, "need 'name' + 'start' + 'size' (>0)"); return;
        }
        Memory mem = prog.getMemory();
        int tx = prog.startTransaction("decepticon mcp: memblocks/create_initialized");
        boolean ok = false;
        String error = null;
        MemoryBlock b = null;
        try {
            byte[] data = new byte[size.intValue()];
            for (int i = 0; i < data.length; i++) data[i] = fill;
            b = mem.createInitializedBlock(name, start, new ByteArrayInputStream(data),
                    size, ghidra.util.task.TaskMonitor.DUMMY, false);
            ok = true;
        } catch (MemoryConflictException | AddressOverflowException e) {
            error = e.getClass().getSimpleName() + ": " + e.getMessage();
        } catch (Exception e) {
            error = e.getClass().getSimpleName() + ": " + e.getMessage();
        } finally {
            prog.endTransaction(tx, ok);
        }
        if (!ok || b == null) { Http.error(ex, 500, error == null ? "create failed" : error); return; }
        Http.ok(ex, Map.of("name", b.getName(), "start", b.getStart().toString(),
            "end", b.getEnd().toString(), "size", b.getSize()));
    }

    // ── /memblocks/create_uninitialized ──────────────────────────────

    public void handleCreateUninitialized(HttpExchange ex) throws IOException {
        Program prog = pa.currentProgram();
        if (prog == null) { Http.error(ex, 503, "no program loaded"); return; }
        Map<String, String> q = Http.parseQuery(ex.getRequestURI().getQuery());
        String name = q.get("name");
        Address start = prog.getAddressFactory().getAddress(q.getOrDefault("start", ""));
        Long size = parseLongOrNull(q.get("size"));
        if (name == null || start == null || size == null || size <= 0) {
            Http.error(ex, 400, "need 'name' + 'start' + 'size'"); return;
        }
        Memory mem = prog.getMemory();
        int tx = prog.startTransaction("decepticon mcp: memblocks/create_uninitialized");
        boolean ok = false;
        String error = null;
        MemoryBlock b = null;
        try {
            b = mem.createUninitializedBlock(name, start, size, false);
            ok = true;
        } catch (Exception e) {
            error = e.getClass().getSimpleName() + ": " + e.getMessage();
        } finally {
            prog.endTransaction(tx, ok);
        }
        if (!ok || b == null) { Http.error(ex, 500, error == null ? "create failed" : error); return; }
        Http.ok(ex, Map.of("name", b.getName(), "start", b.getStart().toString(),
            "end", b.getEnd().toString(), "size", b.getSize()));
    }

    // ── /memblocks/delete ────────────────────────────────────────────

    public void handleDelete(HttpExchange ex) throws IOException {
        Program prog = pa.currentProgram();
        if (prog == null) { Http.error(ex, 503, "no program loaded"); return; }
        Map<String, String> q = Http.parseQuery(ex.getRequestURI().getQuery());
        String name = q.get("name");
        if (name == null) { Http.error(ex, 400, "missing 'name'"); return; }
        Memory mem = prog.getMemory();
        MemoryBlock b = null;
        for (MemoryBlock cand : mem.getBlocks()) if (cand.getName().equals(name)) { b = cand; break; }
        if (b == null) { Http.error(ex, 404, "no block " + name); return; }
        int tx = prog.startTransaction("decepticon mcp: memblocks/delete");
        boolean ok = false;
        String error = null;
        try {
            mem.removeBlock(b, ghidra.util.task.TaskMonitor.DUMMY);
            ok = true;
        } catch (Exception e) {
            error = e.getClass().getSimpleName() + ": " + e.getMessage();
        } finally {
            prog.endTransaction(tx, ok);
        }
        if (!ok) { Http.error(ex, 500, error); return; }
        Http.ok(ex, Map.of("name", name, "deleted", true));
    }

    // ── /memblocks/rename ────────────────────────────────────────────

    public void handleRename(HttpExchange ex) throws IOException {
        Program prog = pa.currentProgram();
        if (prog == null) { Http.error(ex, 503, "no program loaded"); return; }
        Map<String, String> q = Http.parseQuery(ex.getRequestURI().getQuery());
        String name = q.get("name");
        String newName = q.get("new_name");
        if (name == null || newName == null) { Http.error(ex, 400, "need 'name' + 'new_name'"); return; }
        MemoryBlock b = findBlock(prog, name);
        if (b == null) { Http.error(ex, 404, "no block " + name); return; }
        int tx = prog.startTransaction("decepticon mcp: memblocks/rename");
        boolean ok = false;
        String error = null;
        try {
            b.setName(newName);
            ok = true;
        } catch (Exception e) {
            error = e.getClass().getSimpleName() + ": " + e.getMessage();
        } finally {
            prog.endTransaction(tx, ok);
        }
        if (!ok) { Http.error(ex, 500, error); return; }
        Http.ok(ex, Map.of("old_name", name, "new_name", newName));
    }

    // ── /memblocks/set_permissions ───────────────────────────────────

    public void handleSetPermissions(HttpExchange ex) throws IOException {
        Program prog = pa.currentProgram();
        if (prog == null) { Http.error(ex, 503, "no program loaded"); return; }
        Map<String, String> q = Http.parseQuery(ex.getRequestURI().getQuery());
        String name = q.get("name");
        if (name == null) { Http.error(ex, 400, "missing 'name'"); return; }
        MemoryBlock b = findBlock(prog, name);
        if (b == null) { Http.error(ex, 404, "no block " + name); return; }
        Map<String, Object> applied = new HashMap<>();
        int tx = prog.startTransaction("decepticon mcp: memblocks/set_permissions");
        try {
            if (q.containsKey("read"))    { boolean v = "true".equalsIgnoreCase(q.get("read"));    b.setRead(v);    applied.put("read", v); }
            if (q.containsKey("write"))   { boolean v = "true".equalsIgnoreCase(q.get("write"));   b.setWrite(v);   applied.put("write", v); }
            if (q.containsKey("execute")) { boolean v = "true".equalsIgnoreCase(q.get("execute")); b.setExecute(v); applied.put("execute", v); }
            if (q.containsKey("volatile")){ boolean v = "true".equalsIgnoreCase(q.get("volatile"));b.setVolatile(v);applied.put("volatile", v); }
        } finally {
            prog.endTransaction(tx, true);
        }
        Http.ok(ex, Map.of("name", name, "applied", applied));
    }

    // ── /memblocks/split ─────────────────────────────────────────────

    public void handleSplit(HttpExchange ex) throws IOException {
        Program prog = pa.currentProgram();
        if (prog == null) { Http.error(ex, 503, "no program loaded"); return; }
        Map<String, String> q = Http.parseQuery(ex.getRequestURI().getQuery());
        String name = q.get("name");
        Address splitAt = prog.getAddressFactory().getAddress(q.getOrDefault("addr", ""));
        if (name == null || splitAt == null) { Http.error(ex, 400, "need 'name' + 'addr'"); return; }
        MemoryBlock b = findBlock(prog, name);
        if (b == null) { Http.error(ex, 404, "no block " + name); return; }
        int tx = prog.startTransaction("decepticon mcp: memblocks/split");
        boolean ok = false;
        String error = null;
        try {
            prog.getMemory().split(b, splitAt);
            ok = true;
        } catch (Exception e) {
            error = e.getClass().getSimpleName() + ": " + e.getMessage();
        } finally {
            prog.endTransaction(tx, ok);
        }
        if (!ok) { Http.error(ex, 500, error); return; }
        Http.ok(ex, Map.of("name", name, "split_at", splitAt.toString()));
    }

    // ── /memblocks/fill ──────────────────────────────────────────────

    public void handleFill(HttpExchange ex) throws IOException {
        Program prog = pa.currentProgram();
        if (prog == null) { Http.error(ex, 503, "no program loaded"); return; }
        Map<String, String> q = Http.parseQuery(ex.getRequestURI().getQuery());
        String name = q.get("name");
        int val = parseIntOr(q.get("value"), 0) & 0xff;
        if (name == null) { Http.error(ex, 400, "missing 'name'"); return; }
        MemoryBlock b = findBlock(prog, name);
        if (b == null || !b.isInitialized()) { Http.error(ex, 404, "no init block " + name); return; }
        int tx = prog.startTransaction("decepticon mcp: memblocks/fill");
        boolean ok = false;
        String error = null;
        try {
            long size = b.getSize();
            byte[] bytes = new byte[(int) Math.min(size, 1024 * 1024L)];
            for (int i = 0; i < bytes.length; i++) bytes[i] = (byte) val;
            // Chunk if larger
            Address cur = b.getStart();
            long remaining = size;
            while (remaining > 0) {
                int chunk = (int) Math.min(remaining, bytes.length);
                prog.getListing().clearCodeUnits(cur, cur.add(chunk - 1L), false);
                prog.getMemory().setBytes(cur, bytes, 0, chunk);
                cur = cur.add(chunk);
                remaining -= chunk;
            }
            ok = true;
        } catch (Exception e) {
            error = e.getClass().getSimpleName() + ": " + e.getMessage();
        } finally {
            prog.endTransaction(tx, ok);
        }
        if (!ok) { Http.error(ex, 500, error); return; }
        Http.ok(ex, Map.of("name", name, "fill_value", String.format("0x%02x", val), "bytes_written", b.getSize()));
    }

    // ── /memblocks/info ──────────────────────────────────────────────

    public void handleInfo(HttpExchange ex) throws IOException {
        Program prog = pa.currentProgram();
        if (prog == null) { Http.error(ex, 503, "no program loaded"); return; }
        Map<String, String> q = Http.parseQuery(ex.getRequestURI().getQuery());
        String name = q.get("name");
        if (name == null) { Http.error(ex, 400, "missing 'name'"); return; }
        MemoryBlock b = findBlock(prog, name);
        if (b == null) { Http.error(ex, 404, "no block " + name); return; }
        Map<String, Object> m = new HashMap<>();
        m.put("name", b.getName());
        m.put("start", b.getStart().toString());
        m.put("end", b.getEnd().toString());
        m.put("size", b.getSize());
        m.put("read", b.isRead());
        m.put("write", b.isWrite());
        m.put("execute", b.isExecute());
        m.put("volatile", b.isVolatile());
        m.put("initialized", b.isInitialized());
        m.put("artificial", b.isArtificial());
        m.put("overlay", b.isOverlay());
        m.put("type", b.getType().toString());
        m.put("comment", b.getComment() == null ? "" : b.getComment());
        Http.ok(ex, m);
    }

    // ── helpers ──────────────────────────────────────────────────────

    private static MemoryBlock findBlock(Program prog, String name) {
        for (MemoryBlock b : prog.getMemory().getBlocks()) if (b.getName().equals(name)) return b;
        return null;
    }

    private static int parseIntOr(String s, int def) {
        if (s == null) return def;
        try {
            if (s.startsWith("0x")) return Integer.parseInt(s.substring(2), 16);
            return Integer.parseInt(s);
        } catch (Exception e) { return def; }
    }

    private static Long parseLongOrNull(String s) {
        if (s == null) return null;
        try {
            if (s.startsWith("0x")) return Long.parseUnsignedLong(s.substring(2), 16);
            return Long.parseLong(s);
        } catch (Exception e) { return null; }
    }
}
