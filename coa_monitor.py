"""
coa_monitor.py  –  Class-of-Architecture (COA) subsystem monitor.

Five subsystems:
  1. MemoryLayoutMonitor  – address-space map, conflict detection, relocation diagnostics
  2. BranchLayoutMonitor  – 2-bit saturating-counter predictor, taken/not-taken history
  3. PipelineLayoutMonitor – simulated 5-stage x86-64 in-order pipeline
  4. CacheLayoutMonitor   – 3-level LRU cache simulation (L1i, L1d, L2, L3)
  5. ProcessingMonitor    – throughput, IPC, stall/flush rates, fault events
"""

from __future__ import annotations
import collections
import math
import struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# ─────────────────────────────────────────────────────────────────
# 1. MEMORY LAYOUT
# ─────────────────────────────────────────────────────────────────

@dataclass
class MemoryConflict:
    kind:    str
    address: int
    detail:  str


class MemoryLayoutMonitor:
    """
    Root-cause taxonomy for dynamic-link failures
    ──────────────────────────────────────────────
    PIE / ET_DYN binaries:
      • All PT_LOAD vaddrs start near 0 (position-independent offsets).
      • Without applying a load_base, segments overlap the null page and
        clobber each other in the flat emulator address space.
      • PT_INTERP (ld-linux) is never mapped in emulation, so every PLT
        call does: call [GOT+n] → GOT holds 0 (un-relocated) →
        fetch @ 0x0 → UC_ERR_FETCH_UNMAPPED.

    R_X86_64_JUMP_SLOT / GLOB_DAT gaps:
      • GOT entries for imported symbols (malloc, printf…) stay 0 until
        the runtime linker runs. Absent ld-linux, each PLT trampoline
        jumps to 0 and crashes.

    Fix (see load_dynamic_into_emulator in analyzer.py):
      • Detect ET_DYN → pick load_base = 0x400000.
      • Offset every PT_LOAD vaddr by load_base.
      • Apply load_base to R_RELATIVE addends.
      • Fill JUMP_SLOT / GLOB_DAT GOT entries with a single-byte int3
        stub trampoline so the emulator stops cleanly on PLT calls.
    """

    LOAD_BASE_PIE = 0x400000

    def __init__(self):
        self.regions:          List[Dict]              = []
        self.conflicts:        List[MemoryConflict]    = []
        self.unmapped_events:  List[Dict]              = []
        self.relocations:      List[Dict]              = []
        self.got_stubs:        Dict[int, str]          = {}
        self.is_pie   = False
        self.load_base = 0

    def ingest_binary(self, analyzer) -> Dict:
        self.is_pie    = analyzer.elf.header.e_type == "ET_DYN"
        self.load_base = self.LOAD_BASE_PIE if self.is_pie else 0
        self.regions   = []

        for seg in analyzer.segments:
            if seg["type"] != "PT_LOAD":
                continue
            base = seg["vaddr"] + self.load_base
            self.regions.append({
                "label": "PT_LOAD",
                "base":  base,
                "size":  seg["memsz"],
                "flags": seg["flags"],
                "rx":    bool(seg["flags"] & 1),
                "rw":    bool(seg["flags"] & 2),
                "ro":    bool(seg["flags"] & 4),
            })

        # Synthetic kernel/runtime regions
        self.regions += [
            {"label": "stack",    "base": 0x7FFF0000,           "size": 0x100000,  "flags": 6},
            {"label": "heap",     "base": 0x10000000,           "size": 0x1000000, "flags": 6},
            {"label": "vdso",     "base": 0x7FFD0000,           "size": 0x2000,    "flags": 5},
            {"label": "vsyscall", "base": 0xFFFFFFFFFF600000,   "size": 0x1000,    "flags": 5},
        ]

        self.relocations = []
        for rel in analyzer.relocations:
            self.relocations.append({
                "offset": rel["offset"] + self.load_base,
                "type":   rel["type"],
                "symbol": rel["symbol"],
                "addend": rel.get("addend", 0),
                "fixup":  self._reloc_action(rel),
            })

        self._detect_overlaps()
        return {
            "is_pie":      self.is_pie,
            "load_base":   self.load_base,
            "regions":     self.regions,
            "conflicts":   [c.__dict__ for c in self.conflicts],
            "relocations": self.relocations,
            "root_cause":  self._root_cause_summary(analyzer),
        }

    def _reloc_action(self, rel: Dict) -> str:
        t   = rel["type"]
        sym = rel["symbol"]
        names = {1:"ABS64", 2:"PC32", 6:"GLOB_DAT", 7:"JUMP_SLOT",
                 8:"RELATIVE", 10:"COPY"}
        name = names.get(t, f"T{t}")
        if t == 8: return f"R_RELATIVE: *GOT = load_base + addend"
        if t == 7: return f"R_JUMP_SLOT({sym}): *GOT = stub_trampoline"
        if t == 6: return f"R_GLOB_DAT({sym}): *GOT = &{sym}"
        return f"R_{name}({sym})"

    def _detect_overlaps(self):
        self.conflicts = []
        rs = sorted(self.regions, key=lambda r: r["base"])
        for i in range(len(rs) - 1):
            a, b = rs[i], rs[i+1]
            if a["base"] + a["size"] > b["base"]:
                self.conflicts.append(MemoryConflict(
                    kind="overlap", address=b["base"],
                    detail=(f'{a["label"]}@0x{a["base"]:x} '
                            f'overlaps {b["label"]}@0x{b["base"]:x}'),
                ))

    def record_unmapped(self, kind: str, address: int):
        self.unmapped_events.append({"kind": kind, "address": address})
        self.conflicts.append(MemoryConflict(
            kind=kind, address=address,
            detail=f"Unmapped {kind} @ 0x{address:x}",
        ))

    def _root_cause_summary(self, analyzer) -> Dict:
        issues = []
        if self.is_pie:
            issues.append({
                "id": "PIE_NO_BASE", "severity": "CRITICAL",
                "title": "PIE binary loaded without load_base offset",
                "detail": (
                    f"ET_DYN binary with entry=0x{analyzer.entry_point:x}. "
                    "All PT_LOAD vaddrs start near 0x0. Without load_base=0x"
                    f"{self.LOAD_BASE_PIE:x}, the first PT_LOAD maps over the null page "
                    "→ NULL-dereferences silently succeed and PLT stubs land at wrong addresses."
                ),
                "fix": (
                    f"Apply load_base=0x{self.LOAD_BASE_PIE:x} to every PT_LOAD vaddr "
                    "and to all R_RELATIVE addends before mapping."
                ),
            })

        got_unresolved = [r for r in self.relocations if r["type"] in (6, 7) and r["symbol"]]
        if got_unresolved:
            syms = list({r["symbol"] for r in got_unresolved})[:6]
            issues.append({
                "id": "GOT_UNRESOLVED", "severity": "CRITICAL",
                "title": "GOT entries for imported symbols remain 0",
                "detail": (
                    f"{len(got_unresolved)} GOT slots need runtime linker resolution "
                    f"(JUMP_SLOT/GLOB_DAT). Without ld-linux in emulation, these stay 0. "
                    f"Affected symbols: {', '.join(syms)}"
                ),
                "fix": (
                    "Install int3 stub trampolines into each JUMP_SLOT GOT entry. "
                    "The emulator's INSN_INVALID hook catches each call and logs the "
                    "symbol name, then stops cleanly."
                ),
            })

        if not self.is_pie and not got_unresolved:
            issues.append({
                "id": "STATIC_OK", "severity": "INFO",
                "title": "Static binary – no dynamic linking issues detected",
                "detail": "All PT_LOAD segments use absolute vaddrs. No GOT relocations.",
                "fix": "None required.",
            })
        return {"issues": issues, "got_unresolved": len(got_unresolved)}


# ─────────────────────────────────────────────────────────────────
# 2. BRANCH LAYOUT  – 2-bit saturating counter predictor
# ─────────────────────────────────────────────────────────────────

BRANCH_MNEMONICS = frozenset({
    "jmp","jo","jno","js","jns","je","jz","jne","jnz",
    "jb","jnae","jc","jnb","jae","jnc","jbe","jna",
    "ja","jnbe","jl","jnge","jge","jnl","jle","jng","jg","jnle",
    "jp","jpe","jnp","jpo","jcxz","jecxz","jrcxz",
    "call","ret","loop","loope","loopne",
    "b","bl","blr","br","bx",           # ARM64
})


class BranchLayoutMonitor:
    """
    2-bit saturating counter predictor (Pentium-style).
    State: 0=strongly NT … 3=strongly T.
    Taken detection: compare next_ip vs (addr + insn_size).
    Instruction size derived from consecutive trace addresses.
    """
    HISTORY_LEN = 1024

    def __init__(self):
        self.predictor: Dict[int, int]         = {}
        self.history:   collections.deque      = collections.deque(maxlen=self.HISTORY_LEN)
        self.stats = {"taken": 0, "not_taken": 0, "mispredicts": 0, "total": 0}

    def ingest_trace(self, entries: List[Dict]):
        for i, e in enumerate(entries):
            mnem = e.get("mnemonic", "").lower().rstrip()
            if mnem not in BRANCH_MNEMONICS:
                continue

            addr = e["address"]

            # Derive instruction size from next trace address when available
            if i + 1 < len(entries):
                next_addr  = entries[i + 1]["address"]
                # For x86 branches: fall-through = addr + insn_size
                # We can't know size directly, but the NEXT executed address
                # tells us whether the branch was taken:
                #   taken     → next_addr ≠ addr + {1..15}  (non-sequential)
                #   not-taken → next_addr = addr + insn_size (sequential)
                # Heuristic: if next_addr - addr is in [1,15] it's fall-through
                gap   = next_addr - addr
                taken = not (1 <= gap <= 15)
            else:
                taken = False

            state   = self.predictor.get(addr, 1)   # start weakly NT
            predict = state >= 2

            if taken:
                self.stats["taken"]     += 1
                state = min(3, state + 1)
            else:
                self.stats["not_taken"] += 1
                state = max(0, state - 1)

            correct = (predict == taken)
            if not correct:
                self.stats["mispredicts"] += 1
            self.stats["total"] += 1

            self.predictor[addr] = state
            self.history.append({
                "address":   addr,
                "mnemonic":  mnem,
                "op_str":    e.get("op_str", ""),
                "taken":     taken,
                "predicted": predict,
                "correct":   correct,
                "state":     state,
                "symbol":    e.get("symbol", ""),
            })

    def get_state(self) -> Dict:
        total    = self.stats["total"] or 1
        hit_rate = round((total - self.stats["mispredicts"]) / total * 100, 2)
        hot_spots = sorted(
            [{"address": a, "state": s,
              "bias": "taken" if s >= 2 else "not-taken",
              "mnemonic": ""}
             for a, s in self.predictor.items()],
            key=lambda x: abs(x["state"] - 1.5), reverse=True,
        )[:20]
        return {
            "stats":             self.stats,
            "hit_rate":          hit_rate,
            "history":           list(self.history)[-100:],
            "hot_spots":         hot_spots,
            "predictor_entries": len(self.predictor),
        }


# ─────────────────────────────────────────────────────────────────
# 3. PIPELINE LAYOUT – 5-stage in-order pipeline model
# ─────────────────────────────────────────────────────────────────

PIPELINE_STAGES = ["Fetch", "Decode", "Execute", "Memory", "WriteBack"]

LATENCY: Dict[str, int] = {
    "nop":1,"endbr64":1,"mov":1,"lea":1,"push":1,"pop":1,
    "add":1,"sub":1,"xor":1,"and":1,"or":1,"not":1,"neg":1,
    "cmp":1,"test":1,"inc":1,"dec":1,
    "imul":3,"mul":3,"div":20,"idiv":20,
    "call":3,"ret":3,
    "jmp":1,"je":1,"jne":1,"jl":1,"jg":1,"jle":1,"jge":1,
    "jb":1,"ja":1,"js":1,"jns":1,"jz":1,"jnz":1,
    "movsx":1,"movzx":1,"movsxd":1,
    "shl":1,"shr":1,"sar":1,"rol":1,"ror":1,
    "xchg":2,"cmovne":2,"cmove":2,"cmovl":2,"cmovg":2,
    "syscall":100,
    "rep":1,"repe":1,"repne":1,
}


class PipelineLayoutMonitor:
    SNAPSHOT_WINDOW = 200

    def __init__(self):
        self.cycle    = 0
        self.stalls   = 0
        self.flushes  = 0
        self.retired  = 0
        self.snapshots: collections.deque = collections.deque(maxlen=self.SNAPSHOT_WINDOW)

    @property
    def ipc(self) -> float:
        return round(self.retired / max(self.cycle, 1), 3)

    @property
    def cpi(self) -> float:
        return round(self.cycle / max(self.retired, 1), 3)

    def ingest_trace(self, entries: List[Dict]):
        for e in entries:
            mnem = e.get("mnemonic", "nop").lower().rstrip()
            lat  = LATENCY.get(mnem, 1)

            has_mem   = bool(e.get("mem_reads") or e.get("mem_writes"))
            is_branch = mnem in BRANCH_MNEMONICS or mnem in ("call", "ret")
            is_syscall = mnem == "syscall"

            stall = 0
            if has_mem:   stall += 1    # load-use hazard
            if is_branch: stall += 1    # branch penalty
            if is_syscall: stall += 5   # pipeline flush for privilege switch

            self.stalls  += stall
            self.flushes += 1 if is_branch else 0
            self.cycle   += lat + stall
            self.retired += 1

            self.snapshots.append({
                "cycle":    self.cycle,
                "address":  e["address"],
                "mnemonic": mnem,
                "latency":  lat,
                "stalls":   stall,
                "stages": {
                    "Fetch":     {"active": True,     "addr": e["address"]},
                    "Decode":    {"active": True,     "addr": e["address"]},
                    "Execute":   {"active": True,     "addr": e["address"], "lat": lat},
                    "Memory":    {"active": has_mem,  "addr": e["address"] if has_mem else 0},
                    "WriteBack": {"active": True,     "addr": e["address"]},
                },
                "hazard": ("syscall" if is_syscall else
                           "branch"  if is_branch  else
                           "load"    if has_mem    else None),
                "symbol": e.get("symbol", ""),
            })

    def get_state(self) -> Dict:
        util = {s: 0 for s in PIPELINE_STAGES}
        for snap in self.snapshots:
            for s in PIPELINE_STAGES:
                if snap["stages"][s]["active"]:
                    util[s] += 1
        n = len(self.snapshots) or 1
        util = {s: round(v / n * 100, 1) for s, v in util.items()}
        return {
            "cycle":       self.cycle,
            "retired":     self.retired,
            "stalls":      self.stalls,
            "flushes":     self.flushes,
            "ipc":         self.ipc,
            "cpi":         self.cpi,
            "utilisation": util,
            "snapshots":   list(self.snapshots)[-50:],
        }


# ─────────────────────────────────────────────────────────────────
# 4. CACHE LAYOUT – 3-level LRU cache simulation
# ─────────────────────────────────────────────────────────────────

class LRUCache:
    def __init__(self, size_bytes: int, line_size: int, ways: int, name: str):
        self.name      = name
        self.size      = size_bytes
        self.line_size = line_size
        self.ways      = ways
        self.sets      = max(1, size_bytes // (line_size * ways))
        self.hits      = 0
        self.misses    = 0
        self.tags: Dict[int, collections.deque] = {}

    def access(self, address: int) -> bool:
        tag     = address >> int(math.log2(self.line_size))
        set_idx = tag % self.sets
        lru     = self.tags.setdefault(set_idx, collections.deque())
        if tag in lru:
            lru.remove(tag)
            lru.appendleft(tag)
            self.hits += 1
            return True
        if len(lru) >= self.ways:
            lru.pop()
        lru.appendleft(tag)
        self.misses += 1
        return False

    @property
    def hit_rate(self) -> float:
        t = self.hits + self.misses
        return round(self.hits / t * 100, 2) if t else 0.0

    def summary(self) -> Dict:
        return {
            "name":           self.name,
            "size":           self.size,
            "ways":           self.ways,
            "sets":           self.sets,
            "line_size":      self.line_size,
            "hits":           self.hits,
            "misses":         self.misses,
            "hit_rate":       self.hit_rate,
            "total":          self.hits + self.misses,
            "occupied_sets":  len(self.tags),
        }


class CacheLayoutMonitor:
    """Skylake-like L1i/L1d/L2/L3 hierarchy with write-allocate LRU model."""

    def __init__(self):
        self.l1i = LRUCache(32_768,    64, 8,  "L1-Instruction")
        self.l1d = LRUCache(32_768,    64, 8,  "L1-Data")
        self.l2  = LRUCache(262_144,   64, 4,  "L2-Unified")
        self.l3  = LRUCache(8_388_608, 64, 16, "L3-Unified")
        self.access_log: collections.deque = collections.deque(maxlen=500)

    def _access(self, address: int, kind: str):
        l1 = self.l1d if kind == "data" else self.l1i
        if l1.access(address):
            level = 1
        elif self.l2.access(address):
            level = 2
        else:
            self.l3.access(address)
            level = 3 if (self.l3.hits + self.l3.misses) and self.l3.hits else 4
        self.access_log.append({"address": address, "kind": kind, "level": level})

    def ingest_trace(self, entries: List[Dict]):
        for e in entries:
            self._access(e["address"], "instruction")
            for addr, _ in e.get("mem_reads", []):
                self._access(addr, "data")
            for addr, _, _ in e.get("mem_writes", []):
                self._access(addr, "data")

    def get_state(self) -> Dict:
        levels = [self.l1i, self.l1d, self.l2, self.l3]
        level_hits = [0, 0, 0, 0]
        for ev in self.access_log:
            idx = min(ev["level"] - 1, 3)
            level_hits[idx] += 1
        total = len(self.access_log) or 1
        return {
            "levels":         [c.summary() for c in levels],
            "access_log":     list(self.access_log)[-100:],
            "level_dist":     [round(h / total * 100, 1) for h in level_hits],
            "total_accesses": len(self.access_log),
        }


# ─────────────────────────────────────────────────────────────────
# 5. PROCESSING MONITOR – throughput, faults, run segments
# ─────────────────────────────────────────────────────────────────

class ProcessingMonitor:
    def __init__(self):
        self.run_segments:   List[Dict] = []
        self.fault_events:   List[Dict] = []
        self.breakpoint_hits = 0
        self.watchpoint_hits = 0
        self._seg_start_insn  = 0
        self._seg_start_cycle = 0
        self._throughput_window: collections.deque = collections.deque(maxlen=30)

    def begin_run(self, insn_count: int, cycle: int):
        self._seg_start_insn  = insn_count
        self._seg_start_cycle = cycle

    def end_run(self, insn_count: int, cycle: int, reason: str):
        delta_i = insn_count - self._seg_start_insn
        delta_c = max(cycle  - self._seg_start_cycle, 1)
        tp      = round(delta_i / delta_c, 3)
        self._throughput_window.append(tp)
        self.run_segments.append({
            "insns":      delta_i,
            "cycles":     delta_c,
            "throughput": tp,
            "reason":     reason,
        })

    def record_fault(self, kind: str, address: int, detail: str):
        self.fault_events.append({"kind": kind, "address": address, "detail": detail})

    def get_state(self, pipeline: PipelineLayoutMonitor) -> Dict:
        avg_tp = (sum(self._throughput_window) / len(self._throughput_window)
                  if self._throughput_window else 0)
        r = pipeline.retired or 1
        c = pipeline.cycle   or 1
        return {
            "total_insns":     pipeline.retired,
            "total_cycles":    pipeline.cycle,
            "ipc":             pipeline.ipc,
            "cpi":             pipeline.cpi,
            "throughput_ipc":  round(avg_tp, 3),
            "stall_rate":      round(pipeline.stalls  / c * 100, 2),
            "flush_rate":      round(pipeline.flushes / r * 100, 2),
            "breakpoint_hits": self.breakpoint_hits,
            "watchpoint_hits": self.watchpoint_hits,
            "run_segments":    self.run_segments[-30:],
            "fault_events":    self.fault_events[-30:],
        }


# ─────────────────────────────────────────────────────────────────
# Top-level facade
# ─────────────────────────────────────────────────────────────────

class COAMonitor:
    def __init__(self):
        self.memory     = MemoryLayoutMonitor()
        self.branch     = BranchLayoutMonitor()
        self.pipeline   = PipelineLayoutMonitor()
        self.cache      = CacheLayoutMonitor()
        self.processing = ProcessingMonitor()
        self._last_trace_len = 0

    def load_binary(self, analyzer) -> Dict:
        return self.memory.ingest_binary(analyzer)

    def update_from_emulator(self, emulator) -> None:
        """Incrementally pull new trace entries and feed all subsystems."""
        new_entries = emulator.get_trace_json(self._last_trace_len, 5000)
        if not new_entries:
            return
        self.branch.ingest_trace(new_entries)
        self.pipeline.ingest_trace(new_entries)
        self.cache.ingest_trace(new_entries)
        self._last_trace_len += len(new_entries)

    def record_unmapped(self, kind: str, address: int):
        self.memory.record_unmapped(kind, address)
        self.processing.record_fault(kind, address, f"Unmapped {kind} @ 0x{address:x}")

    def snapshot_before_run(self):
        self.processing.begin_run(self.pipeline.retired, self.pipeline.cycle)

    def snapshot_after_run(self, reason: str):
        self.processing.end_run(self.pipeline.retired, self.pipeline.cycle, reason)

    def get_all(self, emulator=None) -> Dict:
        if emulator:
            self.update_from_emulator(emulator)
        return {
            "memory": {
                "regions":     self.memory.regions,
                "conflicts":   [c.__dict__ for c in self.memory.conflicts],
                "relocations": self.memory.relocations[:50],
                "unmapped":    self.memory.unmapped_events[-20:],
                "is_pie":      self.memory.is_pie,
                "load_base":   self.memory.load_base,
            },
            "branch":     self.branch.get_state(),
            "pipeline":   self.pipeline.get_state(),
            "cache":      self.cache.get_state(),
            "processing": self.processing.get_state(self.pipeline),
        }
