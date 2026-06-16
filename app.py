"""
app.py - Flask REST API for ELF binary emulation and reverse engineering.

API Endpoints:
  POST /api/upload              - Upload and parse ELF binary
  GET  /api/info                - Binary metadata summary
  GET  /api/sections            - ELF sections list
  GET  /api/segments            - ELF segments list
  GET  /api/symbols             - Symbol table
  GET  /api/strings             - Extracted strings
  GET  /api/disasm              - Disassemble text section or range
  POST /api/emulate/start       - Start/resume emulation
  POST /api/emulate/stop        - Stop emulation
  POST /api/emulate/step        - Single-step N instructions
  POST /api/emulate/reset       - Reset emulator to initial state
  GET  /api/state               - Current emulator state (regs, IP, etc.)
  GET  /api/registers           - All registers
  POST /api/registers           - Write a register value
  GET  /api/memory              - Read memory range
  POST /api/memory              - Write memory bytes
  GET  /api/stack               - Stack frame dump
  GET  /api/breakpoints         - List breakpoints
  POST /api/breakpoints         - Add breakpoint
  DELETE /api/breakpoints/<addr>- Remove breakpoint
  PUT  /api/breakpoints/<addr>  - Toggle breakpoint
  GET  /api/trace               - Execution trace (paginated)
  GET  /api/trace/stats         - Trace analysis stats
  GET  /api/syscalls            - Syscall trace
  GET  /api/heatmap             - Memory access heatmap
  GET  /api/insn_freq           - Instruction frequency
  GET  /api/functions           - Detected function entry points
  GET  /api/callstack           - Reconstructed call stack
"""

import io
import logging
import os
import struct
import threading
from typing import Optional

from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS

from analyzer import ELFAnalyzer, analyse_trace, disassemble_bytes, disassemble_region
from emulator import ELFEmulator

# ──────────────────────────────────────────────
# App setup
# ──────────────────────────────────────────────

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

app = Flask(__name__, static_folder="static", template_folder="templates")
CORS(app, origins="*")

app.config["MAX_CONTENT_LENGTH"] = 32 * 1024 * 1024  # 32 MB max upload

# Global state (single session; extend to dict of session_id for multi-user)
_analyzer: Optional[ELFAnalyzer] = None
_emulator: Optional[ELFEmulator] = None
_elf_data: Optional[bytes] = None
_emu_thread: Optional[threading.Thread] = None
_state_lock = threading.Lock()


def _require_binary():
    if _analyzer is None:
        return jsonify({"error": "No binary loaded"}), 400
    return None


def _require_emulator():
    err = _require_binary()
    if err:
        return err
    if _emulator is None or _emulator.uc is None:
        return jsonify({"error": "Emulator not initialised; load a binary first"}), 400
    return None


# ──────────────────────────────────────────────
# Static / index
# ──────────────────────────────────────────────

@app.route("/")
def index():
    return send_from_directory("templates", "index.html")


@app.route("/static/<path:path>")
def static_files(path):
    return send_from_directory("static", path)


# ──────────────────────────────────────────────
# Binary upload & parsing
# ──────────────────────────────────────────────

@app.route("/api/upload", methods=["POST"])
def upload():
    """
    POST /api/upload
    Body: multipart form-data with field 'file' containing ELF binary.
    Returns: binary summary JSON.
    """
    global _analyzer, _emulator, _elf_data, _emu_thread

    if "file" not in request.files:
        return jsonify({"error": "No file field in request"}), 400

    f = request.files["file"]
    if not f.filename:
        return jsonify({"error": "Empty filename"}), 400

    data = f.read()
    if len(data) < 4 or data[:4] != b"\x7fELF":
        return jsonify({"error": "Not a valid ELF binary"}), 422

    try:
        with _state_lock:
            if _emulator and _emulator._running:
                _emulator.stop()
            _elf_data = data
            _analyzer = ELFAnalyzer(data)
            _emulator = ELFEmulator(_analyzer.arch)
            _analyzer.load_into_emulator(_emulator)
            _emu_thread = None
            # Init COA monitor
            global _coa
            _coa = COAMonitor()
            _coa.load_binary(_analyzer)

        logger.info("Loaded %s (%d bytes) arch=%s", f.filename, len(data), _analyzer.arch)
        return jsonify({
            "status": "ok",
            "filename": f.filename,
            **_analyzer.summary(),
        })
    except Exception as e:
        logger.exception("Upload error")
        return jsonify({"error": str(e)}), 500


# ──────────────────────────────────────────────
# Binary info & structure
# ──────────────────────────────────────────────

@app.route("/api/info")
def info():
    """GET /api/info - ELF summary metadata."""
    err = _require_binary()
    if err: return err
    return jsonify(_analyzer.summary())


@app.route("/api/sections")
def sections():
    """GET /api/sections - List all ELF sections."""
    err = _require_binary()
    if err: return err
    return jsonify(_analyzer.sections)


@app.route("/api/segments")
def segments():
    """GET /api/segments - List all ELF program headers (segments)."""
    err = _require_binary()
    if err: return err
    return jsonify(_analyzer.segments)


@app.route("/api/symbols")
def symbols():
    """GET /api/symbols - Full symbol table."""
    err = _require_binary()
    if err: return err
    syms = [{"name": k, "address": v} for k, v in _analyzer.symbols.items()]
    return jsonify({"symbols": syms, "imports": _analyzer.imports, "exports": _analyzer.exports})


@app.route("/api/strings")
def strings():
    """GET /api/strings - Static strings extracted from binary."""
    err = _require_binary()
    if err: return err
    return jsonify(_analyzer.strings)


@app.route("/api/relocations")
def relocations():
    """GET /api/relocations - Relocation entries."""
    err = _require_binary()
    if err: return err
    return jsonify(_analyzer.relocations)


@app.route("/api/functions")
def functions():
    """GET /api/functions - Detected function entry points (heuristic + symbols)."""
    err = _require_binary()
    if err: return err
    detected = _analyzer.detect_functions()
    # Merge with exported symbols of type STT_FUNC
    for sym in _analyzer.exports:
        if sym.get("type") == "STT_FUNC" and sym["address"] not in {f["address"] for f in detected}:
            detected.append({"address": sym["address"], "name": sym["name"], "confidence": "symbol"})
    detected.sort(key=lambda x: x["address"])
    return jsonify(detected)


# ──────────────────────────────────────────────
# Disassembly
# ──────────────────────────────────────────────

@app.route("/api/disasm")
def disasm():
    """
    GET /api/disasm
    Query params:
      addr    - hex start address (default: entry point)
      size    - bytes to disassemble (default: 512)
      max     - max instructions (default: 200)
    """
    err = _require_binary()
    if err: return err

    addr = int(request.args.get("addr", _analyzer.entry_point), 16) \
           if request.args.get("addr", "").startswith("0x") \
           else int(request.args.get("addr", _analyzer.entry_point))
    size = int(request.args.get("size", 512))
    max_insns = int(request.args.get("max", 200))

    insns = _analyzer.disassemble_at(addr, size, _emulator)
    return jsonify(insns[:max_insns])


@app.route("/api/disasm/section/<name>")
def disasm_section(name):
    """GET /api/disasm/section/<name> - Disassemble a named section."""
    err = _require_binary()
    if err: return err
    data, base = _analyzer.get_section_data(name)
    if data is None:
        return jsonify({"error": f"Section '{name}' not found"}), 404
    insns = disassemble_region(data, base, _analyzer.arch)
    return jsonify(insns)


# ──────────────────────────────────────────────
# Emulation control
# ──────────────────────────────────────────────

@app.route("/api/emulate/start", methods=["POST"])
def emu_start():
    """
    POST /api/emulate/start
    Body JSON:
      begin   - start address (hex or int, default: entry_point)
      until   - stop address (hex or int, optional)
      timeout - microseconds (default: 2_000_000 = 2 s)
      count   - max instructions (default: 100_000)
    Returns: emulator state after run.
    """
    global _emu_thread
    err = _require_emulator()
    if err: return err

    body  = request.get_json(silent=True) or {}
    begin = body.get("begin", _emulator.entry_point)
    if isinstance(begin, str): begin = int(begin, 16)
    until   = int(body.get("until",   0xFFFFFFFFFFFFFFFF))
    timeout = int(body.get("timeout", 2_000_000))
    count   = int(body.get("count",   100_000))

    coa = _get_coa()
    coa.snapshot_before_run()
    with _state_lock:
        _emulator._stopped = False
        _emulator.start(begin, until, timeout=timeout, count=count)
    reason = "breakpoint" if _emulator._stopped else "timeout"
    coa.snapshot_after_run(reason)
    return jsonify(_emulator.get_state())


@app.route("/api/emulate/stop", methods=["POST"])
def emu_stop():
    """POST /api/emulate/stop - Stop running emulation."""
    if _emulator:
        _emulator.stop()
    return jsonify({"status": "stopped"})


@app.route("/api/emulate/step", methods=["POST"])
def emu_step():
    """
    POST /api/emulate/step
    Body JSON:
      count - number of instructions to step (default: 1)
    Returns: state after step.
    """
    err = _require_emulator()
    if err: return err

    body  = request.get_json(silent=True) or {}
    count = int(body.get("count", 1))
    coa   = _get_coa()
    coa.snapshot_before_run()
    state = _emulator.step(count)
    coa.snapshot_after_run("step")
    return jsonify(state)


@app.route("/api/emulate/reset", methods=["POST"])
def emu_reset():
    """POST /api/emulate/reset - Reload binary into a fresh emulator."""
    global _emulator
    err = _require_binary()
    if err: return err

    with _state_lock:
        _emulator = ELFEmulator(_analyzer.arch)
        _analyzer.load_into_emulator(_emulator)

    return jsonify({"status": "reset", "ip": _emulator.entry_point})


# ──────────────────────────────────────────────
# State & registers
# ──────────────────────────────────────────────

@app.route("/api/state")
def state():
    """GET /api/state - Full emulator state snapshot."""
    err = _require_emulator()
    if err: return err
    return jsonify(_emulator.get_state())


@app.route("/api/registers", methods=["GET", "POST"])
def registers():
    """
    GET  /api/registers         - All register values.
    POST /api/registers         - Write register.
      Body: {"name": "rax", "value": "0x1234"}
    """
    err = _require_emulator()
    if err: return err

    if request.method == "GET":
        return jsonify(_emulator.read_registers())

    body = request.get_json(silent=True) or {}
    name  = body.get("name", "")
    value = body.get("value", 0)
    if isinstance(value, str):
        value = int(value, 16) if value.startswith("0x") else int(value)
    ok = _emulator.write_register(name, value)
    return jsonify({"ok": ok, "register": name, "value": value})


# ──────────────────────────────────────────────
# Memory
# ──────────────────────────────────────────────

@app.route("/api/memory", methods=["GET", "POST"])
def memory():
    """
    GET  /api/memory?addr=0x400000&size=256  - Read memory as hex.
    POST /api/memory                          - Write memory bytes.
      Body: {"addr": "0x600000", "data": "deadbeef"}  (hex string)
    """
    err = _require_emulator()
    if err: return err

    if request.method == "GET":
        addr_s = request.args.get("addr", "")
        size   = int(request.args.get("size", 256))
        if not addr_s:
            return jsonify({"error": "addr required"}), 400
        addr = int(addr_s, 16) if addr_s.startswith("0x") else int(addr_s)
        try:
            data = _emulator.read_memory(addr, min(size, 4096))
            # Build annotated hex rows
            rows = []
            width = 16
            for i in range(0, len(data), width):
                chunk = data[i:i+width]
                rows.append({
                    "addr": addr + i,
                    "hex": chunk.hex(),
                    "ascii": "".join(chr(b) if 32 <= b < 127 else "." for b in chunk),
                })
            return jsonify({"addr": addr, "size": len(data), "rows": rows})
        except RuntimeError as e:
            return jsonify({"error": str(e)}), 400

    # POST
    body = request.get_json(silent=True) or {}
    addr_s = body.get("addr", "")
    hex_s  = body.get("data", "")
    if not addr_s or not hex_s:
        return jsonify({"error": "addr and data required"}), 400
    addr = int(addr_s, 16) if addr_s.startswith("0x") else int(addr_s)
    try:
        data = bytes.fromhex(hex_s)
    except ValueError:
        return jsonify({"error": "Invalid hex data"}), 400
    ok = _emulator.write_memory(addr, data)
    return jsonify({"ok": ok})


@app.route("/api/stack")
def stack():
    """GET /api/stack?depth=32 - Stack dump from current RSP."""
    err = _require_emulator()
    if err: return err
    depth = int(request.args.get("depth", 24))
    return jsonify(_emulator.read_stack(depth))


@app.route("/api/regions")
def regions():
    """GET /api/regions - Mapped memory regions."""
    err = _require_emulator()
    if err: return err
    return jsonify([
        {"base": r.base, "size": r.size, "perms": r.perms, "label": r.label}
        for r in _emulator.regions
    ])


# ──────────────────────────────────────────────
# Breakpoints & watchpoints
# ──────────────────────────────────────────────

@app.route("/api/breakpoints", methods=["GET", "POST"])
def breakpoints():
    """
    GET  /api/breakpoints - List all breakpoints.
    POST /api/breakpoints - Add breakpoint.
      Body: {"addr": "0x401000", "condition": null, "type": "exec"}
    """
    err = _require_emulator()
    if err: return err

    if request.method == "GET":
        return jsonify(_emulator.list_breakpoints())

    body = request.get_json(silent=True) or {}
    addr_s = body.get("addr", "")
    if not addr_s:
        return jsonify({"error": "addr required"}), 400
    addr = int(addr_s, 16) if isinstance(addr_s, str) and addr_s.startswith("0x") else int(str(addr_s), 16) if isinstance(addr_s, str) else addr_s
    cond   = body.get("condition")
    bp_type = body.get("type", "exec")
    bp = _emulator.add_breakpoint(addr, cond, bp_type)
    return jsonify({"ok": True, "address": addr, "type": bp_type})


@app.route("/api/breakpoints/<string:addr_s>", methods=["DELETE", "PUT"])
def breakpoint_by_addr(addr_s):
    """
    DELETE /api/breakpoints/<addr> - Remove breakpoint at addr.
    PUT    /api/breakpoints/<addr> - Toggle breakpoint.
    """
    err = _require_emulator()
    if err: return err

    addr = int(addr_s, 16) if addr_s.startswith("0x") else int(addr_s)
    if request.method == "DELETE":
        _emulator.remove_breakpoint(addr)
        return jsonify({"ok": True})
    # PUT = toggle
    enabled = _emulator.toggle_breakpoint(addr)
    return jsonify({"ok": True, "enabled": enabled})


# ──────────────────────────────────────────────
# Trace & analysis
# ──────────────────────────────────────────────

@app.route("/api/trace")
def trace():
    """
    GET /api/trace?start=0&limit=200
    Paginated execution trace.
    """
    err = _require_emulator()
    if err: return err
    start = int(request.args.get("start", 0))
    limit = int(request.args.get("limit", 200))
    return jsonify({
        "total": len(_emulator.trace),
        "start": start,
        "entries": _emulator.get_trace_json(start, limit),
    })


@app.route("/api/trace/stats")
def trace_stats():
    """GET /api/trace/stats - Aggregated trace analysis."""
    err = _require_emulator()
    if err: return err
    raw = _emulator.get_trace_json(0, len(_emulator.trace))
    return jsonify(analyse_trace(raw))


@app.route("/api/trace/reset", methods=["POST"])
def trace_reset():
    """POST /api/trace/reset - Clear execution trace."""
    err = _require_emulator()
    if err: return err
    _emulator.reset_trace()
    return jsonify({"ok": True})


@app.route("/api/syscalls")
def syscalls():
    """GET /api/syscalls - All recorded syscall invocations."""
    err = _require_emulator()
    if err: return err
    return jsonify(_emulator.syscall_trace)


@app.route("/api/heatmap")
def heatmap():
    """GET /api/heatmap?top=100 - Memory access heatmap."""
    err = _require_emulator()
    if err: return err
    top = int(request.args.get("top", 100))
    return jsonify(_emulator.get_heatmap_json(top))


@app.route("/api/insn_freq")
def insn_freq():
    """GET /api/insn_freq - Instruction mnemonic frequency."""
    err = _require_emulator()
    if err: return err
    freq = sorted(_emulator.insn_freq.items(), key=lambda x: x[1], reverse=True)
    return jsonify([{"mnemonic": m, "count": c} for m, c in freq[:50]])


@app.route("/api/runtime_strings")
def runtime_strings():
    """GET /api/runtime_strings - Strings written during execution."""
    err = _require_emulator()
    if err: return err
    return jsonify([{"addr": k, "value": v} for k, v in _emulator.runtime_strings.items()])


@app.route("/api/callstack")
def callstack():
    """GET /api/callstack - Reconstructed call chain from trace."""
    err = _require_emulator()
    if err: return err
    # Walk trace backwards to reconstruct calls
    calls = []
    for e in reversed(_emulator.trace[-200:]):
        if e.mnemonic in ("call", "bl", "blr"):
            addr = e.address
            sym  = _emulator.rev_symbols.get(addr, "")
            calls.append({"address": addr, "symbol": sym})
    return jsonify(calls[:20])


# ──────────────────────────────────────────────
# Health
# ──────────────────────────────────────────────

@app.route("/api/health")
def health():
    return jsonify({
        "status": "ok",
        "binary_loaded": _analyzer is not None,
        "emulator_ready": _emulator is not None and _emulator.uc is not None,
    })


# ──────────────────────────────────────────────
# Entry
# ──────────────────────────────────────────────

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000, threaded=True)

# ══════════════════════════════════════════════════════════════════════
# COA (Class-of-Architecture) Monitor  –  routes
# ══════════════════════════════════════════════════════════════════════
from coa_monitor import COAMonitor
from analyzer import load_dynamic_into_emulator

_coa: Optional[COAMonitor] = None


def _get_coa() -> COAMonitor:
    global _coa
    if _coa is None:
        _coa = COAMonitor()
    return _coa


@app.route("/api/coa/all")
def coa_all():
    """GET /api/coa/all  –  Full snapshot of all 5 COA subsystems."""
    err = _require_emulator()
    if err: return err
    return jsonify(_get_coa().get_all(_emulator))


@app.route("/api/coa/memory")
def coa_memory():
    """GET /api/coa/memory  –  Memory layout, conflicts, relocation map."""
    err = _require_emulator()
    if err: return err
    coa = _get_coa()
    return jsonify({
        "regions":     coa.memory.regions,
        "conflicts":   [c.__dict__ for c in coa.memory.conflicts],
        "relocations": coa.memory.relocations[:100],
        "unmapped":    coa.memory.unmapped_events[-50:],
        "is_pie":      coa.memory.is_pie,
        "load_base":   coa.memory.load_base,
        "root_cause":  coa.memory._root_cause_summary(_analyzer) if _analyzer else {},
    })


@app.route("/api/coa/branch")
def coa_branch():
    """GET /api/coa/branch  –  Branch predictor state and history."""
    err = _require_emulator()
    if err: return err
    coa = _get_coa()
    coa.update_from_emulator(_emulator)
    return jsonify(coa.branch.get_state())


@app.route("/api/coa/pipeline")
def coa_pipeline():
    """GET /api/coa/pipeline  –  5-stage pipeline occupancy and IPC."""
    err = _require_emulator()
    if err: return err
    coa = _get_coa()
    coa.update_from_emulator(_emulator)
    return jsonify(coa.pipeline.get_state())


@app.route("/api/coa/cache")
def coa_cache():
    """GET /api/coa/cache  –  L1/L2/L3 hit rates and access log."""
    err = _require_emulator()
    if err: return err
    coa = _get_coa()
    coa.update_from_emulator(_emulator)
    return jsonify(coa.cache.get_state())


@app.route("/api/coa/processing")
def coa_processing():
    """GET /api/coa/processing  –  Throughput, IPC, fault events."""
    err = _require_emulator()
    if err: return err
    coa = _get_coa()
    coa.update_from_emulator(_emulator)
    return jsonify(coa.processing.get_state(coa.pipeline))


@app.route("/api/coa/root_cause")
def coa_root_cause():
    """GET /api/coa/root_cause  –  Dynamic linking failure diagnosis."""
    err = _require_binary()
    if err: return err
    coa = _get_coa()
    return jsonify({
        "root_cause": coa.memory._root_cause_summary(_analyzer),
        "unmapped_events": coa.memory.unmapped_events[-50:],
        "got_stubs": coa.memory.got_stubs,
    })


@app.route("/api/upload/dynamic", methods=["POST"])
def upload_dynamic():
    """
    POST /api/upload/dynamic
    Same as /api/upload but uses the dynamic loader:
    applies load_base for PIE, patches GOT stubs for imported symbols.
    Body: multipart form-data with field 'file'.
    """
    global _analyzer, _emulator, _elf_data, _coa

    if "file" not in request.files:
        return jsonify({"error": "No file field"}), 400

    f = request.files["file"]
    data = f.read()
    if len(data) < 4 or data[:4] != b"\x7fELF":
        return jsonify({"error": "Not a valid ELF binary"}), 422

    try:
        with _state_lock:
            if _emulator and _emulator._running:
                _emulator.stop()
            _elf_data  = data
            _analyzer  = ELFAnalyzer(data)
            _emulator  = ELFEmulator(_analyzer.arch)
            _coa       = COAMonitor()

            result = load_dynamic_into_emulator(_analyzer, _emulator)
            coa_mem = _coa.load_binary(_analyzer)

        summary = _analyzer.summary()
        summary.update(result)
        summary["coa_memory"] = coa_mem
        return jsonify({"status": "ok", "filename": f.filename, **summary})

    except Exception as e:
        logger.exception("Dynamic upload error")
        return jsonify({"error": str(e)}), 500
