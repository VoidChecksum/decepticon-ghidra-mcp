# Agentic RE / 0-day Workflows

The 6 canonical workflows enabled by chaining tools from `TOOL_CATALOG.md`.
Each combines 3-5 tools into a single agent-driven loop.

## 1. Diff-based 0-day discovery via BSim

The single highest-leverage 0-day-discovery workflow exposed in this MCP.
Replicates BinDiff / Diaphora workflow agentically, headless, at scale.

**Inputs**: a patched binary (e.g. `vmlinux-5.10.220` w/ CVE fix landed)
+ an unpatched binary (`vmlinux-5.10.215`).

**Chain**:
1. `ghidra_load_binary_with_loader(patched_vmlinux)` (Tier 5, #26)
2. For each function in patched: `ghidra_bsim_generate_signature(addr)` (#5)
   → builds BSim corpus
3. `ghidra_load_binary_with_loader(unpatched_vmlinux)` (#26)
4. For each function in unpatched: `ghidra_bsim_query_function(addr, threshold=0.85)`
   (#4) → returns matches in patched corpus
5. Filter by similarity score delta ≥ threshold (functions that CHANGED)
6. For each changed fn: `ghidra_decompile_function(both versions)` (LaurieWired)
   → LLM diffs the two decompilations
7. LLM identifies the security-relevant delta
8. Promote to KG: `kg_add_node(kind="vulnerability", label="<CVE-candidate>")`

**Outcome**: ranked list of CVE-candidate functions in the unpatched binary,
each w/ evidence excerpt of what changed in the patched version.

## 2. Source→sink taint via P-code

Architecture-independent vuln hunting. Works on x86, ARM, MIPS, RISC-V, etc.
because P-code is Ghidra's IR.

**Inputs**: target binary + sink list (`strcpy`, `system`, `memcpy`, kernel
`copy_from_user`, etc).

**Chain**:
1. `ghidra_list_imports()` (LaurieWired) → find each sink in the import table
2. For each sink: `ghidra_search_xrefs_by_type(type="CALL")` (#23)
3. At each call site: `ghidra_pcode_slice_backward(addr, varnode_id=arg_index)` (#2)
4. `ghidra_pcode_value_set_analysis(slice)` (#17) → resolve indirect calls en-route
5. Filter slices that reach PARAM/LOAD-from-user-controlled-offset
   (i.e. taint sources)
6. Promote: vulnerable call-site chain w/ confidence

**Outcome**: ranked source→sink reachability paths w/ taint evidence.

## 3. Cross-binary symbol port via Version Tracking

70%+ reduction in re-RE labor across firmware revisions.

**Inputs**: an annotated binary (`firmware_v1.bin` w/ symbols + types
hand-curated) + new binary (`firmware_v2.bin`).

**Chain**:
1. `ghidra_load_binary_with_loader(v2)` (#26)
2. `ghidra_analyze_program(v2, baseline_passes)` (#33)
3. `ghidra_version_tracking_correlate(src=v1, dst=v2, correlator="ExactMatchBytes")` (#6)
   → high-confidence matches
4. Apply markup from v1 → v2 (for each match, port name/type/comment)
5. `ghidra_version_tracking_correlate(... correlator="ExactMatchMnemonics")` on remaining
6. Final correlator pass: `correlator="SymbolName"` to catch renames
7. Agent pass on unmatched-only set (LLM analyzes diffs of decompilation)

**Outcome**: 70%+ of v2 fully labeled from v1 w/o human effort. Remainder
flagged for focused analysis.

## 4. Decomp-quality-driven iterative analysis

Initial decomp produces `undefined4 FUN_00401234(undefined4 param_1, undefined8 param_2)` — useless. Iteratively improve by feeding type info back.

**Chain**:
1. `ghidra_decompile_function(addr)` (LaurieWired) → measure "undefined" count
2. `ghidra_demangle_symbol(<imported symbol>)` (#21) → name hint
3. `ghidra_import_header_file(SDK_header.h)` (#12) → SDK types available
4. `ghidra_set_function_prototype(addr, informed_signature)` (LaurieWired/extended)
5. `ghidra_decompile_with_options(addr, style="aggressive")` (#20)
6. Measure: lower "undefined" count, recovered locals via
   `ghidra_high_function_symbols(addr)` (#16)
7. If delta > 0: propagate via xrefs (#23) to callers, re-decompile them
8. Cascading type inference until fixpoint

**Outcome**: stripped binary's decompilation reaches readable C w/ proper
struct accesses + named locals.

## 5. Coverage-guided fuzz harness extraction

Automate the harness-writing for AFL++ / libFuzzer.

**Inputs**: target function X to fuzz.

**Chain**:
1. `ghidra_decompile_function(X)` (LaurieWired) → understand input shape
2. `ghidra_high_function_symbols(X)` (#16) → recovered signature
3. `ghidra_dominator_analysis(X)` (#19) → constraints needed to reach interesting basic blocks
4. For each branch condition: `ghidra_pcode_slice_backward(branch_varnode)` (#2)
   → find input bytes that gate coverage
5. Emit harness skeleton w/ struct layouts derived from
   `ghidra_apply_struct_at_addr` (#11) results
6. `ghidra_emulate_function(X, regs={...}, mem=[...])` (#8) → validate
   harness compiles + runs entry path before handoff to fuzzer

**Outcome**: ready-to-fuzz `harness.c` + `corpus/seed-001.bin` skeleton.

## 6. Statically-linked library identification + skip

Stripped binary, 8000 functions. Filter out the boring 2000 + focus the
LLM-analysis pass on the 6000 unknown.

**Chain**:
1. `ghidra_fid_apply()` (#30) → FidDB hits libc, OpenSSL, zlib functions
2. Auto-renames ~2000 functions
3. `ghidra_function_tags_set(matched_fns, tag="library")` (#22)
4. Subsequent vuln-hunt queries filter out tagged set:
   `ghidra_search_xrefs_by_type(type="CALL", exclude_tag="library")` (#23)
5. Agent focuses on 6000 unknown functions where the bug actually lives

**Outcome**: 3x reduction in agent attention waste on library code.

---

## Composing workflows

For real engagements, agents typically combine 2-3 workflows:

**Firmware audit pipeline**:
- Workflow 6 (strip library noise) → Workflow 4 (improve decomp quality)
  → Workflow 2 (taint hunt sinks) → Workflow 5 (build fuzz harnesses for
  remaining surface)

**CVE-research pipeline**:
- Workflow 1 (BSim diff vs patched) → Workflow 3 (port symbols to other
  vulnerable versions) → produce CVE PoC candidates at scale

**0-day hunting pipeline**:
- Workflow 6 (strip libs) → Workflow 2 (taint analysis) → Workflow 5 (build
  fuzz harness for promising chains) → fuzz w/ AFL++ → crash triage via
  `ghidra_emulate_function`

Each pipeline is an agent loop that chains MCP tool calls. Decepticon's
`reverser` agent is the natural consumer; standalone Claude Code w/ MCP
client also works.
