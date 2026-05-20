# Decepticon Ghidra MCP — Complete Tool Catalog (36 tools)

Full catalog organized by tier (priority + Ghidra-API complexity). v0.1 ships
Tier 1 (8 tools). Subsequent releases populate the remaining 28.

## Tier 1 — P-code + BSim core (v0.1 — SHIPPED)

The 8 tools that unlock agentic workflows no existing Ghidra MCP supports.

### 1. `ghidra_pcode_emit_function`
- **Ghidra API**: `ghidra.app.decompiler.DecompInterface.decompileFunction()` → `HighFunction.getPcodeOps()`
- **Purpose**: Get raw + high P-code ops for every instruction in a function
- **Why it matters**: Architecture-independent taint analysis — P-code is Ghidra's IR; sink/source identification works across x86/ARM/MIPS/RISC-V w/o per-ISA grammar
- **In**: `{addr, simplification="register"|"normalize"|"decompile"}`
- **Out**: list of P-code ops, each `{mnemonic, inputs[Varnode], output[Varnode], sequence}`

### 2. `ghidra_pcode_slice_backward`
- **Ghidra API**: `HighFunction.getPcodeOps()` + walk `Varnode.getDef()`
- **Purpose**: Backward dataflow slice from a Varnode (e.g. sink argument)
- **Use**: Trace where untrusted input flows from. Chain: `xrefs_to(strcpy) → slice_backward(arg) → check if it reaches PARAM/LOAD from user-controlled offset`
- **In**: `{addr, varnode_id, max_depth=20}`
- **Out**: list of ancestor P-code ops with their Varnodes

### 3. `ghidra_pcode_slice_forward`
- **Ghidra API**: Walk `Varnode.getDescendants()` from a starting op
- **Purpose**: Forward def-use chain — where does this value go?
- **Pair w/ #2**: source→sink reachability for taint analysis

### 4. `ghidra_bsim_query_function`
- **Ghidra API**: `ghidra.features.bsim.query.BSimClientFactory.querySimilar()`
- **Purpose**: Submit a fn signature vector to a BSim DB → ranked similar fns across corpus
- **Use**: **Diff-based 0-day discovery**. Index a patched kernel → query unpatched fn against the patched index → high-similarity-but-not-identical matches identify the security-relevant delta
- **In**: `{addr, db_url, threshold=0.85, max_results=20}`
- **Out**: `[{exe_name, fn_name, similarity_score, addr}, ...]`

### 5. `ghidra_bsim_generate_signature`
- **Ghidra API**: `ghidra.features.bsim.gui.BSimGuiUtils.generateSignatures()`
- **Purpose**: Pre-compute BSim signature(s) for a binary or specific function
- **Pair w/ #4**: build the corpus, then query against it

### 6. `ghidra_version_tracking_correlate`
- **Ghidra API**: `ghidra.feature.vt.api.main.VTSessionDB` + `VTProgramCorrelator`
- **Purpose**: Match two binaries via Exact Bytes / Exact Mnemonics / Reference / Symbol-Name correlator
- **Use**: **N-day port** — auto-port symbols + types + comments from a CVE-fixed binary to an unpatched target. 70%+ reduction in re-RE labor across firmware revisions
- **In**: `{src_binary, dst_binary, correlator="ExactMatchBytes"|"ExactMatchMnemonics"|"Reference"|"SymbolName"}`
- **Out**: match list w/ confidence scores

### 7. `ghidra_run_script`
- **Ghidra API**: `ghidra.app.script.GhidraScript.run()` via `GhidraScriptUtil`
- **Purpose**: Eval arbitrary Jython/Java in Ghidra context
- **Why**: Escape hatch — anything not directly exposed becomes accessible. Backstop for everything not in tiers 1-6
- **In**: `{language="python"|"java", source, args}`
- **Out**: `{stdout, return_value, error}`

### 8. `ghidra_emulate_function`
- **Ghidra API**: `ghidra.app.emulator.EmulatorHelper`
- **Purpose**: SLEIGH P-code emulator — dry-run a function w/ synthetic inputs
- **Use**: **Automated fuzz harness extraction**. Validates that a generated harness compiles + runs the entry path w/ synthetic input before handing off to AFL++/libFuzzer. Avatar2-class capability native in Ghidra
- **In**: `{addr, regs={...}, mem=[...], stop_at, max_instructions=10000}`
- **Out**: final state — registers, memory excerpts, executed-instruction count

---

## Tier 2 — Data types + headers (v0.2 planned)

7 tools for type-driven analysis. Without these, decompilation stays at `undefined4 FUN_00401234()`.

### 9. `ghidra_create_struct`
- **API**: `StructureDataType` + `DataTypeManager.addDataType()`
- **In**: `{name, fields:[{name, type, offset}], packing="DEFAULT"|"DISABLED"}`

### 10. `ghidra_create_enum`
- **API**: `EnumDataType`
- **Use**: Syscall numbers, ioctl codes

### 11. `ghidra_apply_struct_at_addr`
- **API**: `Listing.createData(addr, struct)`
- **Use**: Overlay struct on memory

### 12. `ghidra_import_header_file`
- **API**: `ghidra.app.util.cparser.C.CParser.parse()`
- **Use**: Parse `.h` → DataTypeManager. Feed kernel headers, auto-type all syscall handlers

### 13. `ghidra_import_gdt`
- **API**: `FileDataTypeManager.openFileArchive()`
- **Use**: Load `.gdt` archive (Win SDK, POSIX, Linux kernel pre-built)

### 14. `ghidra_list_data_types`
- **API**: `DataTypeManager.getAllDataTypes()`
- **In**: `{filter_by_source, name_pattern}`

### 15. `ghidra_set_global_var_type`
- **API**: `Listing.getDataAt().getDataType()` setter
- **Bug**: LaurieWired only does locals

---

## Tier 3 — P-code slicing + emulation extensions (v0.2 planned)

5 tools deepening the P-code analysis surface beyond Tier 1.

### 16. `ghidra_high_function_symbols`
- **API**: `HighFunction.getLocalSymbolMap()`
- **Use**: Get decomp-recovered vars w/ storage. Better than disasm-level locals

### 17. `ghidra_pcode_value_set_analysis`
- **API**: Custom via `SymbolicPropagator` + `ConstantPropagationAnalyzer`
- **Use**: Recover register constants at call sites → resolve indirect calls / function pointer tables

### 18. `ghidra_call_graph_reachability`
- **API**: `ghidra.program.model.block.BasicBlockModel` + BFS
- **In**: `{src, dst, max_depth}`
- **Out**: paths

### 19. `ghidra_dominator_analysis`
- **API**: `ghidra.graph.algo.DominanceAlgorithm`
- **Use**: Find must-execute basic blocks → pre-conditions to reach sink

### 20. `ghidra_decompile_with_options`
- **API**: `DecompInterface.setOptions(DecompileOptions)`
- **Use**: Force max timeout, custom type override, simplify style

---

## Tier 4 — Symbol + cross-reference depth (v0.3 planned)

5 tools for better symbol/xref control.

### 21. `ghidra_demangle_symbol`
- **API**: `ghidra.app.util.demangler.DemanglerUtil.demangle()`
- **Handles**: GNU/MSVC/Itanium/Rust/Swift mangled names

### 22. `ghidra_function_tags_set`
- **API**: `Function.addTag()`
- **Use**: Programmatic tagging for cohort hunts

### 23. `ghidra_search_xrefs_by_type`
- **API**: `ReferenceManager.getReferencesTo()` filtered by `RefType.{CONDITIONAL_CALL, UNCONDITIONAL_CALL, DATA, READ, WRITE, PTR}`
- **Bug**: Existing LaurieWired returns all xrefs unfiltered

### 24. `ghidra_assemble_patch`
- **API**: `ghidra.app.plugin.assembler.Assemblers.getAssembler()`
- **Use**: Reassemble instruction at addr → PoC patching, instrumentation, fault-injection harness
- **In**: `{addr, asm="mov rax, 0x1337"}`

### 25. `ghidra_function_create_at_addr`
- **API**: `FunctionManager.createFunction()`
- **Use**: Force-create fn where Ghidra missed entry point

---

## Tier 5 — Loading + headless + project (v0.3 planned)

5 tools for batch + multi-binary work.

### 26. `ghidra_load_binary_with_loader`
- **API**: `ghidra.app.util.opinion.LoaderService` w/ explicit loader choice
- **Use**: Raw firmware blobs ("BinaryLoader" + base addr + lang spec)

### 27. `ghidra_headless_run_script`
- **Cmd**: Spawn `analyzeHeadless` subprocess
- **Use**: Batch hunting across N binaries w/o GUI

### 28. `ghidra_load_pdb`
- **API**: `ghidra.app.plugin.core.analysis.PdbUniversalAnalyzer`
- **Use**: Apply Microsoft PDB to PE post-import

### 29. `ghidra_load_dwarf`
- **API**: `ghidra.app.util.bin.format.dwarf.DWARFProgram`
- **Use**: Apply DWARF to ELF post-import

### 30. `ghidra_fid_apply`
- **API**: `ghidra.feature.fid.service.FidService.search()`
- **Use**: Library function ID — auto-identify statically-linked libc/openssl/zlib in stripped binaries

---

## Tier 6 — Bonus essentials (v0.4 planned)

### 31. `ghidra_bookmark_set` / `ghidra_bookmark_list`
- **API**: `BookmarkManager`

### 32. `ghidra_export_program`
- **API**: `ExporterService` → C source / XML / raw bytes / binary patch

### 33. `ghidra_analyze_program`
- **API**: `AutoAnalysisManager.startAnalysis()`
- **In**: `{passes:[...], options:{...}}`

### 34. `ghidra_list_analyzers`
- **API**: `AutoAnalysisManager.getAnalyzers()`
- **Use**: Enumerate available passes w/ options

### 35. `ghidra_golang_rtti_recover`
- **API**: `ghidra.app.plugin.core.analysis.rust.RustStringAnalyzer` / GolangAnalyzer
- **Use**: Restores Go/Rust types + method tables

### 36. `ghidra_emulator_helper_step`
- **API**: `EmulatorHelper.step()` (single-instruction emulation)
- **Use**: Interactive emulation for the harder cases

---

## Workflow integration

See `docs/WORKFLOWS.md` for the 6 canonical agentic workflows these tools enable:
1. Diff-based 0-day discovery via BSim
2. Source→sink taint via P-code
3. Cross-binary symbol port via Version Tracking
4. Decomp-quality-driven iterative analysis
5. Coverage-guided fuzz harness extraction
6. Statically-linked lib identification + skip

Each workflow chains 3-5 of the 36 tools into a single agent-driven loop.
