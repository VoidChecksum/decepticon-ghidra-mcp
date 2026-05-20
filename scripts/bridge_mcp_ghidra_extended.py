#!/usr/bin/env python3
"""Decepticon Ghidra MCP — Python bridge (extended).

Companion to the DecepticonGhidraExtendedPlugin Java plugin. Provides
the FastMCP server agents connect to. Each tool here proxies an HTTP
call to the running Ghidra plugin (default port 8081).

Run alongside LaurieWired's bridge_mcp_ghidra.py — they cooperate:
LaurieWired exposes the basic 27 tools (decompile, list, rename, xref);
this bridge exposes the 8 new advanced tools (P-code, BSim, VT,
emulator, script).

Usage:
    pipx run --spec . bridge-mcp-ghidra-extended
    # OR
    uv run bridge_mcp_ghidra_extended.py

Configure the host's MCP client (Claude Desktop, Cursor, custom):
    {
      "mcpServers": {
        "ghidra-extended": {
          "command": "python3",
          "args": ["/path/to/bridge_mcp_ghidra_extended.py"]
        }
      }
    }
"""

# /// script
# requires-python = ">=3.10"
# dependencies = [
#   "requests>=2,<3",
#   "mcp>=1.2.0,<2",
# ]
# ///

from __future__ import annotations

import argparse
import logging
import os
from typing import Any  # re-used by tool signatures below
from urllib.parse import urljoin

_ = Any  # quiet linters for the re-export of Any

import requests
from mcp.server.fastmcp import FastMCP

logger = logging.getLogger(__name__)

DEFAULT_SERVER = "http://127.0.0.1:8081"

mcp = FastMCP("decepticon-ghidra-mcp-extended")
SERVER_URL = DEFAULT_SERVER


def _get(endpoint: str, params: dict | None = None, timeout: float = 30) -> dict:
    url = urljoin(SERVER_URL, endpoint)
    try:
        r = requests.get(url, params=params or {}, timeout=timeout)
        r.encoding = "utf-8"
        if not r.ok:
            return {"error": f"HTTP {r.status_code}", "body": r.text}
        try:
            return r.json()
        except ValueError:
            return {"error": "non-json response", "body": r.text[:500]}
    except requests.RequestException as e:
        return {"error": f"request failed: {e}"}


def _post(endpoint: str, body: dict, timeout: float = 60) -> dict:
    url = urljoin(SERVER_URL, endpoint)
    try:
        r = requests.post(url, json=body, timeout=timeout)
        if not r.ok:
            return {"error": f"HTTP {r.status_code}", "body": r.text}
        try:
            return r.json()
        except ValueError:
            return {"error": "non-json response", "body": r.text[:500]}
    except requests.RequestException as e:
        return {"error": f"request failed: {e}"}


# ── Tool definitions ─────────────────────────────────────────────


@mcp.tool()
def ghidra_pcode_emit_function(addr: str, simplification: str = "decompile") -> dict:
    """Get raw + high P-code ops for every instruction in a function.

    Args:
        addr: Function address as hex string (e.g. "0x00401234" or "00401234")
        simplification: One of "register" (basic), "normalize" (medium),
            "decompile" (full, recommended)

    Returns:
        {function, addr, pcode_ops: [{seq, mnemonic, seqnum, inputs, output}, ...]}

    Use cases:
        - Architecture-independent taint analysis
        - Source/sink identification across x86/ARM/MIPS/RISC-V w/o per-ISA grammar
        - Generic IR for symbolic execution
    """
    return _get("/pcode/emit", {"addr": addr, "simplification": simplification})


@mcp.tool()
def ghidra_pcode_slice_backward(addr: str, varnode_id: int, max_depth: int = 20) -> dict:
    """Backward dataflow slice from a Varnode (e.g. sink argument).

    Trace where untrusted input flows from. Chain:
      xrefs_to(strcpy) -> slice_backward(arg) -> reaches PARAM/LOAD?

    Args:
        addr: Address of the call site
        varnode_id: Index of the input Varnode to slice from
        max_depth: Max slice depth

    Returns:
        [{op, varnode, depth}, ...] list of ancestor P-code ops
    """
    return _get(
        "/pcode/slice_backward",
        {"addr": addr, "varnode": str(varnode_id), "max_depth": str(max_depth)},
    )


@mcp.tool()
def ghidra_pcode_slice_forward(addr: str, varnode_id: int, max_depth: int = 20) -> dict:
    """Forward def-use chain — where does this value go?

    Pair w/ slice_backward for source→sink reachability for taint analysis.

    Args:
        addr: Address of the defining op
        varnode_id: Index of the output Varnode
        max_depth: Max slice depth

    Returns:
        [{op, varnode, depth}, ...] list of descendant P-code ops
    """
    return _get(
        "/pcode/slice_forward",
        {"addr": addr, "varnode": str(varnode_id), "max_depth": str(max_depth)},
    )


@mcp.tool()
def ghidra_bsim_query_function(
    addr: str, db_url: str, threshold: float = 0.85, max_results: int = 20
) -> dict:
    """Submit a function signature to a BSim DB → ranked similar functions.

    Use case: Diff-based 0-day discovery — query an unpatched fn against
    a BSim corpus of patched kernels. High-similarity-but-not-identical
    matches identify the security-relevant delta.

    Args:
        addr: Function address in the currently-loaded binary
        db_url: BSim database URL (e.g. "postgresql://bsim@localhost/bsim")
        threshold: Minimum similarity score [0.0..1.0]
        max_results: Max matches to return

    Returns:
        [{exe_name, fn_name, similarity_score, addr}, ...] matches in the corpus
    """
    return _get(
        "/bsim/query",
        {
            "addr": addr,
            "db": db_url,
            "threshold": str(threshold),
            "max_results": str(max_results),
        },
    )


@mcp.tool()
def ghidra_bsim_generate_signature(addr: str) -> dict:
    """Pre-compute BSim signature for a function (for indexing).

    Pair w/ ghidra_bsim_query_function: build the corpus, then query.

    Args:
        addr: Function address

    Returns:
        {signature: base64-encoded sig}
    """
    return _get("/bsim/signature", {"addr": addr})


@mcp.tool()
def ghidra_version_tracking_correlate(
    src_binary: str, dst_binary: str, correlator: str = "ExactMatchBytes"
) -> dict:
    """Match two binaries via Version Tracking correlator.

    Use case: N-day port — auto-port symbols/types/comments from
    a CVE-fixed binary to an unpatched target. 70%+ reduction in
    re-RE labor across firmware revisions.

    Args:
        src_binary: Path to the annotated source binary
        dst_binary: Path to the unannotated destination binary
        correlator: One of "ExactMatchBytes" / "ExactMatchMnemonics" /
            "Reference" / "SymbolName"

    Returns:
        [{src_fn, dst_fn, confidence}, ...] match list w/ scores
    """
    return _get(
        "/vt/correlate",
        {"src": src_binary, "dst": dst_binary, "correlator": correlator},
    )


@mcp.tool()
def ghidra_run_script(language: str, source: str, args: list[str] | None = None) -> dict:
    """Eval arbitrary Jython/Java in Ghidra's script context.

    Escape hatch — anything not directly exposed becomes accessible.

    Args:
        language: "python" (Jython) or "java"
        source: Source code
        args: Optional CLI args passed to the script

    Returns:
        {stdout, return_value, error}
    """
    return _post(
        "/script/run",
        {"language": language, "source": source, "args": args or []},
    )


@mcp.tool()
def ghidra_emulate_function(
    addr: str,
    regs: dict[str, int] | None = None,
    mem: list[dict] | None = None,
    stop_at: str | None = None,
    max_instructions: int = 10000,
) -> dict:
    """Run SLEIGH P-code emulator on a function with synthetic inputs.

    Use case: Automated fuzz harness extraction. Validate a generated
    harness compiles + runs the entry path before handing off to
    AFL++/libFuzzer.

    Args:
        addr: Function entry address
        regs: Initial register values, e.g. {"RDI": 0x1000, "RSI": 0x4000}.
            Pass either int (decimal/hex) or "0xDEADBEEF" string.
        mem: Memory writes, e.g. [{"addr": "0x1000", "data": "deadbeef"}].
            ``data`` is hex-encoded bytes (no spaces, no 0x prefix).
        stop_at: Address to stop emulation at (None = run to max_instructions)
        max_instructions: Hard cap on instructions executed

    Returns:
        {function, entry, executed_instructions, stopped_at, stop_reason,
         final_regs: {REG: "0x..."}, final_mem: [{addr, data}]}
    """
    body: dict[str, Any] = {
        "addr": addr,
        "max_instructions": max_instructions,
    }
    if stop_at:
        body["stop_at"] = stop_at
    if regs:
        # Convert int values to ensure they serialize as JSON numbers
        body["regs"] = {k: int(v) for k, v in regs.items()}
    if mem:
        body["mem"] = mem
    return _post("/emulate", body)


def _try_register_v02_tools():
    """v0.2 tools live in a sibling module to keep this file small.
    Best-effort import — if the sibling isn't present we just skip the
    v0.2 surface."""
    try:
        import importlib.util as _iu
        import os as _os
        sib = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)),
                            "bridge_v02_tools.py")
        if not _os.path.isfile(sib):
            return False
        spec = _iu.spec_from_file_location("bridge_v02_tools", sib)
        mod = _iu.module_from_spec(spec)
        spec.loader.exec_module(mod)
        mod.register_v02_tools(mcp, _get, _post)
        return True
    except Exception as e:
        logger.warning(f"v0.2 tools registration skipped: {e}")
        return False


_try_register_v02_tools()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--server",
        default=os.getenv("GHIDRA_EXT_SERVER", DEFAULT_SERVER),
        help="Ghidra extended plugin URL (default: %(default)s)",
    )
    ap.add_argument(
        "--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"]
    )
    args = ap.parse_args()

    logging.basicConfig(
        level=args.log_level, format="%(asctime)s %(levelname)s %(message)s"
    )
    global SERVER_URL
    SERVER_URL = args.server

    # Probe the plugin server
    health = _get("/health", timeout=2)
    if "error" in health:
        logger.warning(
            f"Ghidra extended plugin not reachable at {SERVER_URL}. "
            "Tool calls will fail until Ghidra is launched + plugin loaded."
        )
    else:
        logger.info(f"Ghidra extended plugin live at {SERVER_URL} (version={health.get('version')})")

    mcp.run()


if __name__ == "__main__":
    main()
