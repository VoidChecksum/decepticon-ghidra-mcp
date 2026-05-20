# decepticon-ghidra-mcp

The most complete Ghidra MCP — exposes the entire Ghidra reverse-engineering
+ 0-day-discovery surface as MCP tools. Extends [LaurieWired/GhidraMCP](https://github.com/LaurieWired/GhidraMCP) (the original Ghidra MCP, ~27 endpoints covering listing/decompile/rename/xref) with **36 additional tools** across P-code analysis, BSim similarity search, Version Tracking, emulation, custom data types, demangler/FidDB/DWARF/PDB loaders, headless analyzer, and assembly patching.

Built for **agentic 0-day discovery + RE automation**. Designed to drop into PurpleAILAB/Decepticon's reverser agent stack but works standalone w/ any MCP-compatible LLM client (Claude Code, Cursor, custom).

## Why a new MCP

LaurieWired's GhidraMCP + pyghidra-mcp (the two existing options) both cover ~30% of Ghidra's surface — same shallow shape: list / decompile / rename / xref. The remaining **70% is where 0-day actually lives**:
- **P-code analysis** — architecture-independent vuln hunting via taint
- **BSim** — fuzzy function similarity → diff-based 0-day discovery
- **Version Tracking** — automated N-day porting
- **Emulation** — fuzz-harness extraction primitives
- **Custom types + headers** — readable decompilation
- **Headless analyzer** — fleet-scale binary corpus analysis

decepticon-ghidra-mcp exposes ALL of this as MCP tools. The complete tool catalog is in `docs/TOOL_CATALOG.md`.

## Status

**v0.1 (this repo's initial commit): 8 tools fully implemented** out of 36 planned. Design doc + Java + Python bridge for the rest in `docs/TOOL_CATALOG.md`.

| Tier | Tools | Status |
|---|---|---|
| 1 (P-code + BSim core) | 8 | **v0.1 — this repo** |
| 2 (Data types + headers) | 7 | v0.2 planned |
| 3 (P-code slicing + emulation) | 5 | v0.2 planned |
| 4 (Symbol + xref depth) | 5 | v0.3 |
| 5 (Loading + headless + project) | 5 | v0.3 |
| 6 (Bonus: bookmarks, export, RTTI) | 4 | v0.4 |

v0.1 tools (all functional):

1. `ghidra_pcode_emit_function` — `HighFunction.getPcodeOps()` access
2. `ghidra_pcode_slice_backward` — backward taint slice from a Varnode
3. `ghidra_pcode_slice_forward` — forward def-use chain
4. `ghidra_bsim_query_function` — fuzzy function similarity search
5. `ghidra_bsim_generate_signature` — BSim signature for indexing
6. `ghidra_version_tracking_correlate` — symbol-port across binaries
7. `ghidra_run_script` — eval arbitrary Jython/Java (escape hatch)
8. `ghidra_emulate_function` — SLEIGH P-code emulator (`EmulatorHelper`)

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                LLM client (Decepticon)              │
└──────────────────────────────┬──────────────────────┘
                               │ MCP STDIO / SSE
┌──────────────────────────────▼──────────────────────┐
│         bridge_mcp_ghidra_extended.py (Python)      │
│  - FastMCP server                                   │
│  - HTTP client to Ghidra plugin endpoints           │
└──────────────────────────────┬──────────────────────┘
                               │ HTTP localhost:8081
┌──────────────────────────────▼──────────────────────┐
│       DecepticonGhidraExtendedPlugin (Java)         │
│  - Extends LaurieWired's GhidraMCPPlugin           │
│  - Adds 8 new endpoints (v0.1)                      │
│  - Direct Ghidra API access (BSim, P-code, etc)     │
└─────────────────────────────────────────────────────┘
```

## Install

```bash
# Prereq: Ghidra 11.x or 12.x installed, $GHIDRA_HOME set
# Prereq: LaurieWired's GhidraMCP installed (provides the base plugin we extend)

cd ~/sec-agents
git clone https://github.com/VoidChecksum/decepticon-ghidra-mcp.git
cd decepticon-ghidra-mcp

# Build the Java plugin
./gradlew buildExtension
# Output: dist/decepticon-ghidra-mcp-extended.zip

# Install in Ghidra:
#   File → Install Extensions → '+' → select the zip
# Restart Ghidra. The DecepticonGhidraExtended plugin will appear in
# Configure → Configure → Decepticon Ghidra MCP.

# Install the Python MCP bridge
pipx install -e .

# Or run directly:
uv run bridge_mcp_ghidra_extended.py
```

## Usage from Decepticon

Add to your `decepticon/agents/reverser.py` agent config (or any MCP-aware agent):

```python
# In the reverser agent's MCP server list
MCP_SERVERS = [
    "decepticon-ghidra-mcp-extended",  # new
    "ghidra-mcp",  # existing (LaurieWired)
]
```

The new tools become available alongside LaurieWired's. Decepticon's reverser agent can now:

```python
# Diff-based 0-day discovery
patched_sig = ghidra_bsim_generate_signature(addr=0x401000, binary="vmlinux-5.10.220")
unpatched_matches = ghidra_bsim_query_function(addr=0x401000, binary="vmlinux-5.10.215", threshold=0.9)
# Returns functions in 5.10.215 that match 5.10.220's patched version
# → those are the candidates for the patched-vuln in the older binary

# Source→sink taint analysis
for sink_call in xrefs_to("strcpy"):
    backward = ghidra_pcode_slice_backward(addr=sink_call, varnode_idx=1)
    if backward.reaches("PARAM") or backward.reaches("USER_INPUT_SOURCE"):
        report_vuln(sink_call, evidence=backward)

# Automated fuzz harness extraction
fn_signature = ghidra_high_function_symbols(addr=target_fn)
dominators = ghidra_dominator_analysis(addr=target_fn)
harness = ghidra_emulate_function(addr=target_fn, regs={...}, mem=[...])
```

## License

GPLv3 (matches Ghidra's license — required for derivative plugins).

## Cross-references

- LaurieWired/GhidraMCP — base plugin we extend
- PurpleAILAB/Decepticon — primary consumer of these tools
- `docs/TOOL_CATALOG.md` — full 36-tool design doc w/ Ghidra API mappings
- `docs/WORKFLOWS.md` — agentic RE workflows enabled by these tools
