/* PatchEndpoints — Tier 5 (in-memory patching).
 *
 *   /patch/assemble           — assemble + write instruction at addr
 *   /patch/nop_range          — overwrite addr..end with arch NOPs
 *   /patch/bookmark           — set bookmark for human review
 *   /patch/write_bytes        — raw byte write
 *   /patch/list_bookmarks     — list all decepticon bookmarks
 */

package io.decepticon.ghidra.endpoints;

import com.sun.net.httpserver.HttpExchange;

import ghidra.app.plugin.assembler.Assembler;
import ghidra.app.plugin.assembler.Assemblers;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;

import io.decepticon.ghidra.util.Http;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public final class PatchEndpoints {

    private static final String DECEPTICON_BOOKMARK_CAT = "DecepticonMCP";

    private final PcodeEndpoints.ProgramAccessor programAccessor;

    public PatchEndpoints(PcodeEndpoints.ProgramAccessor pa) { this.programAccessor = pa; }

    // ── /patch/assemble ──────────────────────────────────────────────

    public void handleAssemble(HttpExchange ex) throws IOException {
        Program prog = programAccessor.currentProgram();
        if (prog == null) { Http.error(ex, 503, "no program loaded"); return; }
        Map<String, String> q = Http.parseQuery(ex.getRequestURI().getQuery());
        Address a = prog.getAddressFactory().getAddress(q.getOrDefault("addr", ""));
        String mnemonic = q.get("instruction");
        if (a == null || mnemonic == null) {
            Http.error(ex, 400, "need 'addr' + 'instruction'");
            return;
        }
        Assembler asm = Assemblers.getAssembler(prog);
        int tx = prog.startTransaction("decepticon mcp: assemble");
        boolean ok = false;
        String error = null;
        byte[] writtenBytes = null;
        try {
            writtenBytes = asm.assembleLine(a, mnemonic);
            ok = true;
        } catch (Exception e) {
            error = e.getClass().getSimpleName() + ": " + e.getMessage();
        } finally {
            prog.endTransaction(tx, ok);
        }
        if (!ok) { Http.error(ex, 400, error); return; }
        StringBuilder hex = new StringBuilder();
        for (byte b : writtenBytes) hex.append(String.format("%02x", b & 0xff));
        Http.ok(ex, Map.of(
            "addr", a.toString(),
            "instruction", mnemonic,
            "bytes_written", writtenBytes.length,
            "bytes_hex", hex.toString()
        ));
    }

    // ── /patch/nop_range ─────────────────────────────────────────────

    public void handleNopRange(HttpExchange ex) throws IOException {
        Program prog = programAccessor.currentProgram();
        if (prog == null) { Http.error(ex, 503, "no program loaded"); return; }
        Map<String, String> q = Http.parseQuery(ex.getRequestURI().getQuery());
        Address start = prog.getAddressFactory().getAddress(q.getOrDefault("start", ""));
        Address end = prog.getAddressFactory().getAddress(q.getOrDefault("end", ""));
        if (start == null || end == null) {
            Http.error(ex, 400, "need 'start' + 'end'");
            return;
        }
        Memory mem = prog.getMemory();
        long len = end.subtract(start) + 1;
        if (len <= 0 || len > 65536) {
            Http.error(ex, 400, "range invalid or > 64KB");
            return;
        }
        byte nopByte = guessNopByte(prog);
        int tx = prog.startTransaction("decepticon mcp: nop_range");
        boolean ok = false;
        String error = null;
        try {
            byte[] nops = new byte[(int) len];
            for (int i = 0; i < nops.length; i++) nops[i] = nopByte;
            mem.setBytes(start, nops);
            // Re-disassemble
            prog.getListing().clearCodeUnits(start, end, false);
            ok = true;
        } catch (MemoryAccessException e) {
            error = "MemoryAccessException: " + e.getMessage();
        } catch (Exception e) {
            error = e.getClass().getSimpleName() + ": " + e.getMessage();
        } finally {
            prog.endTransaction(tx, ok);
        }
        if (!ok) { Http.error(ex, 500, error); return; }
        Http.ok(ex, Map.of(
            "start", start.toString(),
            "end", end.toString(),
            "bytes_written", len,
            "nop_byte", String.format("0x%02x", nopByte & 0xff)
        ));
    }

    // ── /patch/write_bytes ───────────────────────────────────────────

    public void handleWriteBytes(HttpExchange ex) throws IOException {
        Program prog = programAccessor.currentProgram();
        if (prog == null) { Http.error(ex, 503, "no program loaded"); return; }
        Map<String, String> q = Http.parseQuery(ex.getRequestURI().getQuery());
        Address a = prog.getAddressFactory().getAddress(q.getOrDefault("addr", ""));
        String hex = q.get("hex");
        if (a == null || hex == null) {
            Http.error(ex, 400, "need 'addr' + 'hex'");
            return;
        }
        hex = hex.replace(" ", "");
        if (hex.length() % 2 != 0) { Http.error(ex, 400, "hex length must be even"); return; }
        byte[] bytes = new byte[hex.length() / 2];
        try {
            for (int i = 0; i < bytes.length; i++) {
                bytes[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
            }
        } catch (NumberFormatException e) {
            Http.error(ex, 400, "bad hex");
            return;
        }
        int tx = prog.startTransaction("decepticon mcp: write_bytes");
        boolean ok = false;
        String error = null;
        try {
            prog.getMemory().setBytes(a, bytes);
            prog.getListing().clearCodeUnits(a, a.add(bytes.length - 1L), false);
            ok = true;
        } catch (MemoryAccessException e) {
            error = "MemoryAccessException: " + e.getMessage();
        } catch (Exception e) {
            error = e.getClass().getSimpleName() + ": " + e.getMessage();
        } finally {
            prog.endTransaction(tx, ok);
        }
        if (!ok) { Http.error(ex, 500, error); return; }
        Http.ok(ex, Map.of(
            "addr", a.toString(),
            "bytes_written", bytes.length
        ));
    }

    // ── /patch/bookmark ──────────────────────────────────────────────

    public void handleBookmark(HttpExchange ex) throws IOException {
        Program prog = programAccessor.currentProgram();
        if (prog == null) { Http.error(ex, 503, "no program loaded"); return; }
        Map<String, String> q = Http.parseQuery(ex.getRequestURI().getQuery());
        Address a = prog.getAddressFactory().getAddress(q.getOrDefault("addr", ""));
        String comment = q.getOrDefault("comment", "decepticon mcp note");
        String category = q.getOrDefault("category", DECEPTICON_BOOKMARK_CAT);
        if (a == null) { Http.error(ex, 400, "bad addr"); return; }

        BookmarkManager bm = prog.getBookmarkManager();
        int tx = prog.startTransaction("decepticon mcp: bookmark");
        try {
            bm.setBookmark(a, ghidra.program.model.listing.BookmarkType.NOTE, category, comment);
        } finally {
            prog.endTransaction(tx, true);
        }
        Http.ok(ex, Map.of(
            "addr", a.toString(),
            "category", category,
            "comment", comment
        ));
    }

    // ── /patch/list_bookmarks ────────────────────────────────────────

    public void handleListBookmarks(HttpExchange ex) throws IOException {
        Program prog = programAccessor.currentProgram();
        if (prog == null) { Http.error(ex, 503, "no program loaded"); return; }
        Map<String, String> q = Http.parseQuery(ex.getRequestURI().getQuery());
        String filterCategory = q.get("category");
        BookmarkManager bm = prog.getBookmarkManager();
        List<Map<String, Object>> out = new ArrayList<>();
        AddressSetView addrs = bm.getBookmarkAddresses(ghidra.program.model.listing.BookmarkType.NOTE);
        AddressIterator it = addrs.getAddresses(true);
        while (it.hasNext()) {
            Address a = it.next();
            for (Bookmark b : bm.getBookmarks(a, ghidra.program.model.listing.BookmarkType.NOTE)) {
                if (filterCategory != null && !filterCategory.equals(b.getCategory())) continue;
                Map<String, Object> m = new HashMap<>();
                m.put("addr", a.toString());
                m.put("category", b.getCategory());
                m.put("comment", b.getComment());
                out.add(m);
            }
        }
        Http.ok(ex, Map.of("count", out.size(), "bookmarks", out));
    }

    // ── helpers ──────────────────────────────────────────────────────

    private static byte guessNopByte(Program prog) {
        String arch = prog.getLanguage().getProcessor().toString().toLowerCase();
        // Common single-byte NOPs:
        return switch (arch) {
            case "x86", "x86_64", "x86-64" -> (byte) 0x90;          // NOP
            case "arm", "aarch64" -> (byte) 0x00;                   // NOP (placeholder, full 4-byte NOP needs Assembler)
            case "mips" -> (byte) 0x00;                             // SLL $0,$0,0
            default -> (byte) 0x00;
        };
    }
}
