"""Decepticon Ghidra MCP — v0.3 Python bridge extensions.

Adds Tier 7-14 tool wrappers (76 endpoints) on top of v0.1.1 + v0.2.

Usage (auto-loaded by bridge_mcp_ghidra_extended.py):
    from bridge_v03_tools import register_v03_tools
    register_v03_tools(mcp, _get, _post)
"""

from __future__ import annotations


def register_v03_tools(mcp, _get, _post) -> None:

    # ── Tier 7 — Comments + Equates ───────────────────────────────────

    @mcp.tool()
    def ghidra_comment_set(addr: str, comment: str, type: str = "eol") -> dict:
        """Set a comment at addr. type ∈ {eol, pre, post, plate, repeatable}."""
        return _get("/comments/set", {"addr": addr, "comment": comment, "type": type})

    @mcp.tool()
    def ghidra_comment_get(addr: str, type: str | None = None) -> dict:
        """Get comment(s) at addr. Omit type to get all 5 types as a dict."""
        params = {"addr": addr}
        if type:
            params["type"] = type
        return _get("/comments/get", params)

    @mcp.tool()
    def ghidra_comment_clear(addr: str, type: str = "eol") -> dict:
        """Clear comment at addr."""
        return _get("/comments/clear", {"addr": addr, "type": type})

    @mcp.tool()
    def ghidra_comment_list(type: str = "eol", limit: int = 200) -> dict:
        """List all comments of the given type."""
        return _get("/comments/list", {"type": type, "limit": str(limit)})

    @mcp.tool()
    def ghidra_equates_list(limit: int = 500) -> dict:
        """List all defined equates in the program."""
        return _get("/equates/list", {"limit": str(limit)})

    @mcp.tool()
    def ghidra_equates_create(addr: str, name: str, value: int, op_index: int | None = None) -> dict:
        """Create a named equate (optionally bound to instruction op_index)."""
        params = {"addr": addr, "name": name, "value": str(value)}
        if op_index is not None:
            params["op_index"] = str(op_index)
        return _get("/equates/create", params)

    @mcp.tool()
    def ghidra_equates_get_at(addr: str, op_index: int | None = None) -> dict:
        """Equates at addr (optionally for specific op)."""
        params = {"addr": addr}
        if op_index is not None:
            params["op_index"] = str(op_index)
        return _get("/equates/get_at", params)

    @mcp.tool()
    def ghidra_equates_delete(name: str) -> dict:
        return _get("/equates/delete", {"name": name})

    @mcp.tool()
    def ghidra_equates_rename(name: str, new_name: str) -> dict:
        return _get("/equates/rename", {"name": name, "new_name": new_name})

    # ── Tier 8 — Symbols deep ─────────────────────────────────────────

    @mcp.tool()
    def ghidra_symbol_create_label(addr: str, name: str) -> dict:
        return _get("/symbols/create_label", {"addr": addr, "name": name})

    @mcp.tool()
    def ghidra_symbol_delete(addr: str, name: str) -> dict:
        return _get("/symbols/delete", {"addr": addr, "name": name})

    @mcp.tool()
    def ghidra_symbols_at_addr(addr: str) -> dict:
        return _get("/symbols/get_at_addr", {"addr": addr})

    @mcp.tool()
    def ghidra_symbols_by_name(name: str) -> dict:
        return _get("/symbols/get_by_name", {"name": name})

    @mcp.tool()
    def ghidra_symbol_set_primary(addr: str, name: str) -> dict:
        return _get("/symbols/set_primary", {"addr": addr, "name": name})

    @mcp.tool()
    def ghidra_list_namespaces(limit: int = 200) -> dict:
        return _get("/symbols/list_namespaces", {"limit": str(limit)})

    @mcp.tool()
    def ghidra_create_namespace(name: str, parent: str | None = None) -> dict:
        params = {"name": name}
        if parent:
            params["parent"] = parent
        return _get("/symbols/create_namespace", params)

    @mcp.tool()
    def ghidra_create_class(name: str) -> dict:
        return _get("/symbols/create_class", {"name": name})

    @mcp.tool()
    def ghidra_list_class_symbols(limit: int = 500) -> dict:
        return _get("/symbols/list_class_symbols", {"limit": str(limit)})

    @mcp.tool()
    def ghidra_get_label_history(addr: str) -> dict:
        return _get("/symbols/get_label_history", {"addr": addr})

    # ── Tier 9 — Data types advanced ──────────────────────────────────

    @mcp.tool()
    def ghidra_types_create_struct(name: str, size: int = 0) -> dict:
        return _get("/types/create_struct", {"name": name, "size": str(size)})

    @mcp.tool()
    def ghidra_types_add_struct_field(struct: str, field_name: str, field_type: str,
                                       offset: int | None = None) -> dict:
        params = {"struct": struct, "field_name": field_name, "field_type": field_type}
        if offset is not None:
            params["offset"] = str(offset)
        return _get("/types/add_struct_field", params)

    @mcp.tool()
    def ghidra_types_create_union(name: str) -> dict:
        return _get("/types/create_union", {"name": name})

    @mcp.tool()
    def ghidra_types_create_enum(name: str, size: int = 4) -> dict:
        return _get("/types/create_enum", {"name": name, "size": str(size)})

    @mcp.tool()
    def ghidra_types_add_enum_entry(enum: str, entry_name: str, value: int) -> dict:
        return _get("/types/add_enum_entry", {"enum": enum, "entry_name": entry_name, "value": str(value)})

    @mcp.tool()
    def ghidra_types_create_typedef(name: str, base: str) -> dict:
        return _get("/types/create_typedef", {"name": name, "base": base})

    @mcp.tool()
    def ghidra_types_create_pointer(base: str) -> dict:
        return _get("/types/create_pointer", {"base": base})

    @mcp.tool()
    def ghidra_types_create_array(base: str, length: int) -> dict:
        return _get("/types/create_array", {"base": base, "length": str(length)})

    @mcp.tool()
    def ghidra_types_list_categories(limit: int = 500) -> dict:
        return _get("/types/list_categories", {"limit": str(limit)})

    @mcp.tool()
    def ghidra_types_create_category(path: str) -> dict:
        return _get("/types/create_category", {"path": path})

    @mcp.tool()
    def ghidra_types_find_by_name(name: str) -> dict:
        return _get("/types/find_by_name", {"name": name})

    @mcp.tool()
    def ghidra_types_delete(name: str) -> dict:
        return _get("/types/delete", {"name": name})

    # ── Tier 10 — Functions deep ──────────────────────────────────────

    @mcp.tool()
    def ghidra_functions_create(addr: str, name: str | None = None) -> dict:
        params = {"addr": addr}
        if name:
            params["name"] = name
        return _get("/functions/create", params)

    @mcp.tool()
    def ghidra_functions_delete(addr: str) -> dict:
        return _get("/functions/delete", {"addr": addr})

    @mcp.tool()
    def ghidra_functions_set_return_type(addr: str, type: str) -> dict:
        return _get("/functions/set_return_type", {"addr": addr, "type": type})

    @mcp.tool()
    def ghidra_functions_list_parameters(addr: str) -> dict:
        return _get("/functions/list_parameters", {"addr": addr})

    @mcp.tool()
    def ghidra_functions_set_parameter(addr: str, ordinal: int,
                                        name: str | None = None,
                                        type: str | None = None) -> dict:
        params = {"addr": addr, "ordinal": str(ordinal)}
        if name: params["name"] = name
        if type: params["type"] = type
        return _get("/functions/set_parameter", params)

    @mcp.tool()
    def ghidra_functions_list_locals(addr: str) -> dict:
        return _get("/functions/list_locals", {"addr": addr})

    @mcp.tool()
    def ghidra_functions_set_local(addr: str, old_name: str,
                                    name: str | None = None,
                                    type: str | None = None) -> dict:
        params = {"addr": addr, "old_name": old_name}
        if name: params["name"] = name
        if type: params["type"] = type
        return _get("/functions/set_local", params)

    @mcp.tool()
    def ghidra_functions_add_tag(addr: str, tag: str) -> dict:
        return _get("/functions/add_tag", {"addr": addr, "tag": tag})

    @mcp.tool()
    def ghidra_functions_remove_tag(addr: str, tag: str) -> dict:
        return _get("/functions/remove_tag", {"addr": addr, "tag": tag})

    @mcp.tool()
    def ghidra_functions_list_calling_conv() -> dict:
        return _get("/functions/list_calling_conv", {})

    @mcp.tool()
    def ghidra_functions_set_calling_conv(addr: str, calling_convention: str) -> dict:
        return _get("/functions/set_calling_conv",
                    {"addr": addr, "calling_convention": calling_convention})

    @mcp.tool()
    def ghidra_functions_set_attrs(addr: str,
                                    no_return: bool | None = None,
                                    inline: bool | None = None,
                                    varargs: bool | None = None,
                                    custom_storage: bool | None = None) -> dict:
        params = {"addr": addr}
        if no_return is not None:      params["no_return"] = str(no_return).lower()
        if inline is not None:         params["inline"] = str(inline).lower()
        if varargs is not None:        params["varargs"] = str(varargs).lower()
        if custom_storage is not None: params["custom_storage"] = str(custom_storage).lower()
        return _get("/functions/set_attrs", params)

    # ── Tier 11 — References CRUD ─────────────────────────────────────

    @mcp.tool()
    def ghidra_refs_create(src: str, dst: str, ref_type: str = "data",
                            op_index: int = 0) -> dict:
        """ref_type ∈ {data, unconditional_call, conditional_call, ...}"""
        return _get("/refs/create", {"src": src, "dst": dst, "ref_type": ref_type, "op_index": str(op_index)})

    @mcp.tool()
    def ghidra_refs_delete(src: str, dst: str, op_index: int = 0) -> dict:
        return _get("/refs/delete", {"src": src, "dst": dst, "op_index": str(op_index)})

    @mcp.tool()
    def ghidra_refs_set_primary(src: str, dst: str, op_index: int = 0, primary: bool = True) -> dict:
        return _get("/refs/set_primary",
                    {"src": src, "dst": dst, "op_index": str(op_index), "primary": str(primary).lower()})

    @mcp.tool()
    def ghidra_refs_by_type(addr: str, kind: str = "all") -> dict:
        """kind ∈ {call, jump, data, flow, all}"""
        return _get("/refs/by_type", {"addr": addr, "kind": kind})

    @mcp.tool()
    def ghidra_refs_count_to(addr: str) -> dict:
        return _get("/refs/count_to", {"addr": addr})

    @mcp.tool()
    def ghidra_refs_count_from(addr: str) -> dict:
        return _get("/refs/count_from", {"addr": addr})

    @mcp.tool()
    def ghidra_refs_external_only(addr: str) -> dict:
        return _get("/refs/external_only", {"addr": addr})

    # ── Tier 12 — Memory blocks ───────────────────────────────────────

    @mcp.tool()
    def ghidra_memblock_create_initialized(name: str, start: str, size: int, fill: int = 0) -> dict:
        return _get("/memblocks/create_initialized",
                    {"name": name, "start": start, "size": str(size), "fill": str(fill)})

    @mcp.tool()
    def ghidra_memblock_create_uninitialized(name: str, start: str, size: int) -> dict:
        return _get("/memblocks/create_uninitialized",
                    {"name": name, "start": start, "size": str(size)})

    @mcp.tool()
    def ghidra_memblock_delete(name: str) -> dict:
        return _get("/memblocks/delete", {"name": name})

    @mcp.tool()
    def ghidra_memblock_rename(name: str, new_name: str) -> dict:
        return _get("/memblocks/rename", {"name": name, "new_name": new_name})

    @mcp.tool()
    def ghidra_memblock_set_permissions(name: str,
                                         read: bool | None = None,
                                         write: bool | None = None,
                                         execute: bool | None = None,
                                         volatile: bool | None = None) -> dict:
        params = {"name": name}
        for k, v in (("read", read), ("write", write), ("execute", execute), ("volatile", volatile)):
            if v is not None:
                params[k] = str(v).lower()
        return _get("/memblocks/set_permissions", params)

    @mcp.tool()
    def ghidra_memblock_split(name: str, addr: str) -> dict:
        return _get("/memblocks/split", {"name": name, "addr": addr})

    @mcp.tool()
    def ghidra_memblock_fill(name: str, value: int = 0) -> dict:
        return _get("/memblocks/fill", {"name": name, "value": str(value)})

    @mcp.tool()
    def ghidra_memblock_info(name: str) -> dict:
        return _get("/memblocks/info", {"name": name})

    # ── Tier 13 — Listing + CodeUnits ─────────────────────────────────

    @mcp.tool()
    def ghidra_listing_instructions(start: str, end: str | None = None, limit: int = 200) -> dict:
        params = {"start": start, "limit": str(limit)}
        if end: params["end"] = end
        return _get("/listing/instructions", params)

    @mcp.tool()
    def ghidra_listing_instruction_at(addr: str) -> dict:
        return _get("/listing/get_instruction_at", {"addr": addr})

    @mcp.tool()
    def ghidra_listing_data_at(addr: str) -> dict:
        return _get("/listing/get_data_at", {"addr": addr})

    @mcp.tool()
    def ghidra_listing_create_instruction(addr: str) -> dict:
        return _get("/listing/create_instruction", {"addr": addr})

    @mcp.tool()
    def ghidra_listing_create_data(addr: str, type: str) -> dict:
        return _get("/listing/create_data", {"addr": addr, "type": type})

    @mcp.tool()
    def ghidra_listing_clear(start: str, end: str, clear_context: bool = False) -> dict:
        return _get("/listing/clear", {"start": start, "end": end,
                                         "clear_context": str(clear_context).lower()})

    @mcp.tool()
    def ghidra_listing_disassemble_range(start: str, end: str) -> dict:
        return _get("/listing/disassemble_range", {"start": start, "end": end})

    @mcp.tool()
    def ghidra_listing_string_at(addr: str) -> dict:
        return _get("/listing/get_string_at", {"addr": addr})

    @mcp.tool()
    def ghidra_listing_set_fallthrough(addr: str, fallthrough: str | None = None) -> dict:
        """Set or clear (fallthrough=None) the fallthrough override at addr."""
        params = {"addr": addr}
        if fallthrough:
            params["fallthrough"] = fallthrough
        return _get("/listing/set_fallthrough", params)

    # ── Tier 14 — Analysis options ────────────────────────────────────

    @mcp.tool()
    def ghidra_analysis_list_analyzers() -> dict:
        return _get("/analysis/list_analyzers", {})

    @mcp.tool()
    def ghidra_analysis_get_options(group: str | None = None) -> dict:
        params = {}
        if group: params["group"] = group
        return _get("/analysis/get_options", params)

    @mcp.tool()
    def ghidra_analysis_set_option(name: str, value: str, group: str | None = None) -> dict:
        params = {"name": name, "value": value}
        if group: params["group"] = group
        return _get("/analysis/set_option", params)

    @mcp.tool()
    def ghidra_analysis_reanalyze_all() -> dict:
        return _get("/analysis/reanalyze_all", {}, 180.0)

    @mcp.tool()
    def ghidra_analysis_program_changes() -> dict:
        return _get("/analysis/program_changes", {})

    @mcp.tool()
    def ghidra_project_options() -> dict:
        return _get("/project/options", {})

    @mcp.tool()
    def ghidra_project_list_options(group: str) -> dict:
        return _get("/project/list_options", {"group": group})
