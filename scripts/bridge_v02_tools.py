"""Decepticon Ghidra MCP — v0.2 Python bridge extensions.

This module is imported by the main bridge (``bridge_mcp_ghidra_extended``)
and registers an additional 28 @mcp.tool() functions covering Tiers 2–6.

Imports are lazy so the file doesn't break v0.1.1-only deployments. Keep
this file pure-Python; the actual MCP server is owned by the main bridge.

Usage from the main bridge:

    from bridge_v02_tools import register_v02_tools
    register_v02_tools(mcp, _get, _post)
"""

from __future__ import annotations

from typing import Any


def register_v02_tools(mcp, _get, _post) -> None:
    """Attach all v0.2 tools to the given FastMCP instance.

    Args:
        mcp: a FastMCP server (from the main bridge)
        _get: bound function `(endpoint, params, timeout?)` → dict
        _post: bound function `(endpoint, body, timeout?)` → dict
    """

    # ── Tier 2 — Decompiler + renaming ────────────────────────────────

    @mcp.tool()
    def ghidra_decompile_function(addr: str) -> dict:
        """Return full decompiled C source of a function."""
        return _get("/decompile/function", {"addr": addr})

    @mcp.tool()
    def ghidra_decompile_quality(addr: str) -> dict:
        """Heuristic decompile-quality score (0..1) + signal breakdown.

        Use to triage functions worth manual review vs auto-skip.
        """
        return _get("/decompile/quality", {"addr": addr})

    @mcp.tool()
    def ghidra_rename_function(addr: str, name: str) -> dict:
        """Rename a function symbol in the Ghidra DB (USER_DEFINED source)."""
        return _get("/symbols/rename_function", {"addr": addr, "name": name})

    @mcp.tool()
    def ghidra_set_signature(addr: str, signature: str) -> dict:
        """Propose a function signature.

        v0.2: stored as comment until C-parser wiring (v0.2.1).
        """
        return _get("/symbols/set_signature", {"addr": addr, "signature": signature})

    @mcp.tool()
    def ghidra_list_functions(limit: int = 200, offset: int = 0, externals_only: bool = False) -> dict:
        """Paginated list of program functions."""
        return _get("/symbols/list_functions", {
            "limit": str(limit),
            "offset": str(offset),
            "externals_only": "true" if externals_only else "false",
        })

    @mcp.tool()
    def ghidra_list_strings(limit: int = 500, min_length: int = 4, contains: str | None = None) -> dict:
        """Defined string data in the program. Filter by min length + substring."""
        params = {"limit": str(limit), "min_length": str(min_length)}
        if contains:
            params["contains"] = contains
        return _get("/symbols/list_strings", params)

    @mcp.tool()
    def ghidra_list_symbols(limit: int = 1000, prefix: str | None = None) -> dict:
        """All symbols, optionally filtered by prefix."""
        params: dict[str, Any] = {"limit": str(limit)}
        if prefix:
            params["prefix"] = prefix
        return _get("/symbols/list_symbols", params)

    @mcp.tool()
    def ghidra_list_imports() -> dict:
        """External (imported) symbols."""
        return _get("/symbols/list_imports", {})

    @mcp.tool()
    def ghidra_list_exports() -> dict:
        """Exported / external-entry-point symbols."""
        return _get("/symbols/list_exports", {})

    # ── Tier 3 — Call graph ───────────────────────────────────────────

    @mcp.tool()
    def ghidra_callgraph_outgoing(addr: str) -> dict:
        """Callees of the function at ``addr``."""
        return _get("/callgraph/outgoing", {"addr": addr})

    @mcp.tool()
    def ghidra_callgraph_incoming(addr: str) -> dict:
        """Callers of the function at ``addr``."""
        return _get("/callgraph/incoming", {"addr": addr})

    @mcp.tool()
    def ghidra_callgraph_path(src: str, dst: str, max_depth: int = 10) -> dict:
        """BFS shortest path through the call graph from src→dst."""
        return _get("/callgraph/path", {"src": src, "dst": dst, "max_depth": str(max_depth)})

    @mcp.tool()
    def ghidra_callgraph_entrypoints() -> dict:
        """Program entry points (every address tagged as external-entry)."""
        return _get("/callgraph/entrypoints", {})

    @mcp.tool()
    def ghidra_callgraph_leaves(limit: int = 500) -> dict:
        """Functions that call nothing further — likely terminal logic / sinks."""
        return _get("/callgraph/leaves", {"limit": str(limit)})

    # ── Tier 4 — Type recovery ────────────────────────────────────────

    @mcp.tool()
    def ghidra_types_list(limit: int = 500, prefix: str | None = None) -> dict:
        """List all data types in the program."""
        params: dict[str, Any] = {"limit": str(limit)}
        if prefix:
            params["prefix"] = prefix
        return _get("/types/list", params)

    @mcp.tool()
    def ghidra_types_get_struct(name: str) -> dict:
        """Return struct layout (offset, field, type, length) by name."""
        return _get("/types/get_struct", {"name": name})

    @mcp.tool()
    def ghidra_types_apply_struct_at(addr: str, type: str) -> dict:
        """Apply a struct type at an address — instruments the listing."""
        return _get("/types/apply_struct_at", {"addr": addr, "type": type})

    @mcp.tool()
    def ghidra_types_recover_function(addr: str) -> dict:
        """HighFunction-driven type inference for return + params + locals."""
        return _get("/types/recover_function", {"addr": addr})

    @mcp.tool()
    def ghidra_types_list_at_addr(addr: str) -> dict:
        """What data type is currently at this address?"""
        return _get("/types/list_at_addr", {"addr": addr})

    # ── Tier 5 — Patching ─────────────────────────────────────────────

    @mcp.tool()
    def ghidra_patch_assemble(addr: str, instruction: str) -> dict:
        """Assemble + write a single instruction at addr.

        Example: ``ghidra_patch_assemble("0x401234", "JMP 0x401300")``
        """
        return _get("/patch/assemble", {"addr": addr, "instruction": instruction})

    @mcp.tool()
    def ghidra_patch_nop_range(start: str, end: str) -> dict:
        """Overwrite addr range with architecture-appropriate NOPs."""
        return _get("/patch/nop_range", {"start": start, "end": end})

    @mcp.tool()
    def ghidra_patch_write_bytes(addr: str, hex: str) -> dict:
        """Raw byte write — e.g. ``hex="909090"``."""
        return _get("/patch/write_bytes", {"addr": addr, "hex": hex})

    @mcp.tool()
    def ghidra_patch_bookmark(addr: str, comment: str = "decepticon mcp note",
                              category: str = "DecepticonMCP") -> dict:
        """Set a bookmark for human review."""
        return _get("/patch/bookmark", {
            "addr": addr, "comment": comment, "category": category,
        })

    @mcp.tool()
    def ghidra_patch_list_bookmarks(category: str | None = None) -> dict:
        """List all bookmarks (optionally filtered by category)."""
        params = {}
        if category:
            params["category"] = category
        return _get("/patch/list_bookmarks", params)

    # ── Tier 6 — Search + memory + project ────────────────────────────

    @mcp.tool()
    def ghidra_search_bytes(hex: str, limit: int = 100) -> dict:
        """Find byte pattern (?? = wildcard nibble pair).

        Example: ``hex="48895c24??4889"`` matches with one wildcard byte.
        """
        return _get("/search/bytes", {"hex": hex, "limit": str(limit)})

    @mcp.tool()
    def ghidra_search_text(text: str, limit: int = 100) -> dict:
        """Find UTF-8 byte sequence anywhere in mapped memory."""
        return _get("/search/text", {"text": text, "limit": str(limit)})

    @mcp.tool()
    def ghidra_xrefs_to(addr: str, limit: int = 200) -> dict:
        """All references pointing TO an address."""
        return _get("/xrefs/to", {"addr": addr, "limit": str(limit)})

    @mcp.tool()
    def ghidra_xrefs_from(addr: str) -> dict:
        """All references originating FROM an address."""
        return _get("/xrefs/from", {"addr": addr})

    @mcp.tool()
    def ghidra_memory_map() -> dict:
        """List memory blocks (name, range, R/W/X, init status)."""
        return _get("/memory/map", {})

    @mcp.tool()
    def ghidra_memory_read(addr: str, length: int = 64) -> dict:
        """Read raw bytes — returned as hex string. Max 4096 bytes."""
        return _get("/memory/read", {"addr": addr, "length": str(length)})

    @mcp.tool()
    def ghidra_project_info() -> dict:
        """Program metadata: language, processor, endian, image base, ranges."""
        return _get("/project/info", {})

    @mcp.tool()
    def ghidra_project_analyze() -> dict:
        """Kick off auto-analysis across the program (disassemble + re-analyze)."""
        return _get("/project/analyze", {}, 120.0)

    @mcp.tool()
    def ghidra_project_save() -> dict:
        """Persist program DB changes (renames, struct applies, patches)."""
        return _get("/project/save", {}, 60.0)
