# Decepticon Ghidra MCP — Tool Catalog (v0.2.0)

41 HTTP endpoints across 6 tiers. Plugin in `src/main/java/io/decepticon/ghidra/`; Python bridge in `scripts/`.

> All endpoints respect the operator-loaded program — they read whichever binary is currently active in the Ghidra tool. To act on a different file, open it first.

## Version history

| Version | Routes | Notes |
|---|---|---|
| v0.1.0 | 8 | Tier 1 only; 6 of 8 stubbed at HTTP-501 |
| v0.1.1 | 9 | Tier 1 fully implemented/scaffolded; +`/health` |
| **v0.2.0** | **41** | Adds Tier 2 (9) + Tier 3 (5) + Tier 4 (5) + Tier 5 (5) + Tier 6 (9) |

## Tier 1 — P-code + advanced analysis (9 routes)

| HTTP route | Python wrapper | Purpose |
|---|---|---|
| `GET /pcode/emit` | `ghidra_pcode_emit_function` | HighFunction.getPcodeOps — full op list |
| `GET /pcode/slice_backward` | `ghidra_pcode_slice_backward` | Varnode.getDef ancestor walk (taint source) |
| `GET /pcode/slice_forward` | `ghidra_pcode_slice_forward` | Varnode.getDescendants walk (taint sink) |
| `GET /bsim/signature` | `ghidra_bsim_generate_signature` | Function similarity signature |
| `GET /bsim/query` | `ghidra_bsim_query_function` | Submit signature → ranked DB matches |
| `GET /vt/correlate` | `ghidra_version_tracking_correlate` | Cross-binary correlator (5 algorithms supported) |
| `POST /script/run` | `ghidra_run_script` | Eval Jython w/ pre-bound currentProgram |
| `POST /emulate` | `ghidra_emulate_function` | SLEIGH emulator w/ reg+mem pre-state |
| `GET /health` | (probed at bridge start) | Server liveness + program name |

## Tier 2 — Decompiler + renaming (9 routes)

| HTTP route | Python wrapper | Purpose |
|---|---|---|
| `GET /decompile/function` | `ghidra_decompile_function` | Full C source for one function |
| `GET /decompile/quality` | `ghidra_decompile_quality` | Heuristic quality score 0..1 + signals |
| `GET /symbols/rename_function` | `ghidra_rename_function` | USER_DEFINED rename |
| `GET /symbols/set_signature` | `ghidra_set_signature` | Propose prototype (v0.2 stores as comment) |
| `GET /symbols/list_functions` | `ghidra_list_functions` | Paginated function list |
| `GET /symbols/list_strings` | `ghidra_list_strings` | Defined string data (filter by length / substring) |
| `GET /symbols/list_symbols` | `ghidra_list_symbols` | All symbols w/ optional prefix |
| `GET /symbols/list_imports` | `ghidra_list_imports` | External (imported) symbols |
| `GET /symbols/list_exports` | `ghidra_list_exports` | Exported / external-entry symbols |

## Tier 3 — Call graph (5 routes)

| HTTP route | Python wrapper | Purpose |
|---|---|---|
| `GET /callgraph/outgoing` | `ghidra_callgraph_outgoing` | Callees |
| `GET /callgraph/incoming` | `ghidra_callgraph_incoming` | Callers |
| `GET /callgraph/path` | `ghidra_callgraph_path` | BFS shortest src→dst path |
| `GET /callgraph/entrypoints` | `ghidra_callgraph_entrypoints` | All entry points |
| `GET /callgraph/leaves` | `ghidra_callgraph_leaves` | Functions that call nothing further |

## Tier 4 — Type recovery (5 routes)

| HTTP route | Python wrapper | Purpose |
|---|---|---|
| `GET /types/list` | `ghidra_types_list` | All data types (filter by prefix) |
| `GET /types/get_struct` | `ghidra_types_get_struct` | Field-by-field struct layout |
| `GET /types/apply_struct_at` | `ghidra_types_apply_struct_at` | Apply a struct at an address |
| `GET /types/recover_function` | `ghidra_types_recover_function` | HighFunction type inference (return + params + locals) |
| `GET /types/list_at_addr` | `ghidra_types_list_at_addr` | What's the data type at addr? |

## Tier 5 — In-memory patching (5 routes)

| HTTP route | Python wrapper | Purpose |
|---|---|---|
| `GET /patch/assemble` | `ghidra_patch_assemble` | Assemble + write a mnemonic |
| `GET /patch/nop_range` | `ghidra_patch_nop_range` | Overwrite range with arch NOPs |
| `GET /patch/write_bytes` | `ghidra_patch_write_bytes` | Raw byte write |
| `GET /patch/bookmark` | `ghidra_patch_bookmark` | NOTE bookmark for human review |
| `GET /patch/list_bookmarks` | `ghidra_patch_list_bookmarks` | List bookmarks (optional category filter) |

## Tier 6 — Search + memory + project (9 routes)

| HTTP route | Python wrapper | Purpose |
|---|---|---|
| `GET /search/bytes` | `ghidra_search_bytes` | Find byte pattern (`??` wildcards) |
| `GET /search/text` | `ghidra_search_text` | Find UTF-8 substring in memory |
| `GET /xrefs/to` | `ghidra_xrefs_to` | References TO an address |
| `GET /xrefs/from` | `ghidra_xrefs_from` | References FROM an address |
| `GET /memory/map` | `ghidra_memory_map` | Memory block layout (segments, R/W/X) |
| `GET /memory/read` | `ghidra_memory_read` | Read raw bytes (max 4096) |
| `GET /project/info` | `ghidra_project_info` | Language, processor, endian, image base |
| `GET /project/analyze` | `ghidra_project_analyze` | Kick off auto-analysis |
| `GET /project/save` | `ghidra_project_save` | Persist program DB changes |

## Source layout

```
src/main/java/io/decepticon/ghidra/
├── DecepticonGhidraExtendedPlugin.java   — server boot + routing (41 routes)
├── util/
│   ├── Json.java   — no-Gson JSON encoder
│   └── Http.java   — query parse + body slurp + response helpers
└── endpoints/
    ├── PcodeEndpoints.java         — Tier 1: emit + slice (backward/forward)
    ├── ScriptEndpoint.java         — Tier 1: Jython eval
    ├── EmulateEndpoint.java        — Tier 1: SLEIGH emulator (POST body)
    ├── BSimEndpoints.java          — Tier 1: BSim signature + query
    ├── VTEndpoint.java             — Tier 1: Version Tracking
    ├── DecompilerEndpoints.java    — Tier 2: decompile + symbols (9 routes)
    ├── CallGraphEndpoints.java     — Tier 3: call graph (5 routes)
    ├── TypeEndpoints.java          — Tier 4: type recovery (5 routes)
    ├── PatchEndpoints.java         — Tier 5: in-memory patching (5 routes)
    └── SearchEndpoints.java        — Tier 6: search + memory + project (9 routes)
```

```
scripts/
├── bridge_mcp_ghidra_extended.py   — main bridge, registers Tier 1
└── bridge_v02_tools.py             — registers Tier 2–6 (32 @mcp.tool() functions)
```

## Build

```sh
export GHIDRA_HOME=/opt/ghidra_11.0_PUBLIC
mvn package
# → target/decepticon-ghidra-mcp-extended-0.2.0.jar
# Copy to $GHIDRA_HOME/Ghidra/Extensions/ then enable in File → Configure → Decepticon.
```

## Run bridge (operator-side)

```sh
uv run scripts/bridge_mcp_ghidra_extended.py --server http://127.0.0.1:8081
```
