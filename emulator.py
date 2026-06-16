"""
emulator.py - Unicorn Engine wrapper with hooks, breakpoints, and state management.
Supports x86-64 and ARM64 ELF binaries.
"""

import logging
import struct
import threading
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from unicorn import (
    UC_ARCH_ARM64, UC_ARCH_X86,
    UC_HOOK_CODE, UC_HOOK_INSN_INVALID,
    UC_HOOK_MEM_FETCH_UNMAPPED, UC_HOOK_MEM_READ, UC_HOOK_MEM_READ_UNMAPPED,
    UC_HOOK_MEM_WRITE, UC_HOOK_MEM_WRITE_UNMAPPED,
    UC_MEM_READ, UC_MEM_WRITE, UC_MEM_FETCH,
    UC_MODE_64, UC_MODE_ARM,
    UC_PROT_ALL, UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC,
    Uc, UcError,
)
from unicorn.arm64_const import *
from unicorn.x86_const import *

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────
# Data structures
# ──────────────────────────────────────────────

@dataclass
class Breakpoint:
    address: int
    enabled: bool = True
    condition: Optional[str] = None
    hit_count: int = 0
    bp_type: str = "exec"   # exec | read | write | access


@dataclass
class TraceEntry:
    address: int
    mnemonic: str
    op_str: str
    registers: Dict[str, int]
    memory_reads:  List[Tuple[int, int]]        = field(default_factory=list)
    memory_writes: List[Tuple[int, int, int]]   = field(default_factory=list)
    syscall: Optional[Dict] = None


@dataclass
class MemoryRegion:
    base: int
    size: int
    perms: int
    label: str


# ──────────────────────────────────────────────
# Register maps
# ──────────────────────────────────────────────

X86_64_REGS = {
    "rax": UC_X86_REG_RAX, "rbx": UC_X86_REG_RBX,
    "rcx": UC_X86_REG_RCX, "rdx": UC_X86_REG_RDX,
    "rsi": UC_X86_REG_RSI, "rdi": UC_X86_REG_RDI,
    "rsp": UC_X86_REG_RSP, "rbp": UC_X86_REG_RBP,
    "r8":  UC_X86_REG_R8,  "r9":  UC_X86_REG_R9,
    "r10": UC_X86_REG_R10, "r11": UC_X86_REG_R11,
    "r12": UC_X86_REG_R12, "r13": UC_X86_REG_R13,
    "r14": UC_X86_REG_R14, "r15": UC_X86_REG_R15,
    "rip": UC_X86_REG_RIP, "rflags": UC_X86_REG_RFLAGS,
    "cs":  UC_X86_REG_CS,  "ss":  UC_X86_REG_SS,
    "ds":  UC_X86_REG_DS,  "es":  UC_X86_REG_ES,
    "fs":  UC_X86_REG_FS,  "gs":  UC_X86_REG_GS,
}

def _build_arm64_regs():
    import unicorn.arm64_const as _a
    m = {}
    for i in range(29):
        m[f"x{i}"] = getattr(_a, f"UC_ARM64_REG_X{i}", None)
    m.update({
        "x29": UC_ARM64_REG_X29, "x30": UC_ARM64_REG_X30,
        "sp":  UC_ARM64_REG_SP,  "pc":  UC_ARM64_REG_PC,
        "fp":  UC_ARM64_REG_FP,  "lr":  UC_ARM64_REG_LR,
    })
    return {k: v for k, v in m.items() if v is not None}

ARM64_REGS = _build_arm64_regs()

# Linux x86-64 syscall table (partial)
SYSCALL_TABLE_X64 = {
    0: "read", 1: "write", 2: "open", 3: "close",
    4: "stat", 5: "fstat", 6: "lstat", 9: "mmap",
    10: "mprotect", 11: "munmap", 12: "brk",
    20: "writev", 21: "access", 39: "getpid",
    57: "fork", 59: "execve", 60: "exit",
    63: "uname", 102: "getuid", 231: "exit_group",
}


# ──────────────────────────────────────────────
# Main emulator class
# ──────────────────────────────────────────────

class ELFEmulator:
    STACK_BASE = 0x7FFF0000
    STACK_SIZE = 0x00100000   # 1 MB
    HEAP_BASE  = 0x10000000
    HEAP_SIZE  = 0x01000000   # 16 MB

    def __init__(self, arch: str = "x86_64"):
        self.arch = arch
        self.uc: Optional[Uc] = None
        self.regions: List[MemoryRegion] = []
        self.breakpoints:  Dict[int, Breakpoint] = {}
        self.watchpoints:  Dict[int, Breakpoint] = {}
        self.trace: List[TraceEntry] = []
        self.max_trace = 10_000
        self.symbols:     Dict[str, int] = {}
        self.rev_symbols: Dict[int, str] = {}

        self._running   = False
        self._stopped   = False
        self._step_mode = False
        self._lock      = threading.Lock()

        self._cur_reads:  List[Tuple[int, int]]      = []
        self._cur_writes: List[Tuple[int, int, int]] = []

        self.mem_heatmap:    Dict[int, List[int]] = {}
        self.insn_freq:      Dict[str, int]       = {}
        self.syscall_trace:  List[Dict]           = []
        self.runtime_strings: Dict[int, str]      = {}

        self.entry_point = 0
        self.current_ip  = 0

    # ── Init ─────────────────────────────────────

    def init(self, arch: Optional[str] = None):
        if arch:
            self.arch = arch
        if self.arch == "x86_64":
            self.uc = Uc(UC_ARCH_X86, UC_MODE_64)
            self._reg_map = X86_64_REGS
        elif self.arch == "arm64":
            self.uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
            self._reg_map = ARM64_REGS
        else:
            raise ValueError(f"Unsupported arch: {self.arch}")
        self._install_hooks()
        logger.info("Unicorn initialised for %s", self.arch)

    def _install_hooks(self):
        uc = self.uc
        uc.hook_add(UC_HOOK_CODE,              self._on_insn)
        uc.hook_add(UC_HOOK_MEM_READ,          self._on_mem_read)
        uc.hook_add(UC_HOOK_MEM_WRITE,         self._on_mem_write)
        uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED,  self._on_unmapped_mem)
        uc.hook_add(UC_HOOK_MEM_WRITE_UNMAPPED, self._on_unmapped_mem)
        uc.hook_add(UC_HOOK_MEM_FETCH_UNMAPPED, self._on_unmapped_mem)
        uc.hook_add(UC_HOOK_INSN_INVALID,       self._on_invalid_insn)

    # ── Memory management ─────────────────────────

    def map_region(self, base: int, size: int, label: str,
                   perms: int = UC_PROT_ALL, data: bytes = b""):
        """Page-align base+size, map, then write data."""
        page_base = base & ~0xFFF
        offset    = base - page_base
        aligned   = ((offset + size + 0xFFF) >> 12) << 12
        if aligned == 0:
            aligned = 0x1000

        try:
            self.uc.mem_map(page_base, aligned, perms)
        except UcError:
            pass   # region already mapped (overlapping PT_LOAD segments)

        if data:
            try:
                self.uc.mem_write(base, data)
            except UcError as e:
                logger.warning("mem_write @ 0x%x failed: %s", base, e)

        self.regions.append(MemoryRegion(page_base, aligned, perms, label))
        logger.debug("Mapped %s @ 0x%x size=0x%x", label, page_base, aligned)

    def setup_stack(self):
        """Build an ABI-compliant initial stack.

        x86-64 SysV ABI: RSP on _start entry points at argc (a qword),
        followed by argv[], envp[], and auxv[] each NULL-terminated.
        Without this, _start pops a bad argc → corrupts RDI → calls main
        with garbage → main returns → _start does 'call exit(rax)' →
        exit jumps to address 0 → UC_ERR_FETCH_UNMAPPED.
        """
        self.map_region(self.STACK_BASE, self.STACK_SIZE, "stack")
        sp_top = self.STACK_BASE + self.STACK_SIZE - 0x200

        if self.arch == "x86_64":
            def q(v): return struct.pack("<Q", v & 0xFFFFFFFFFFFFFFFF)

            # Write fake program-name string near top of stack
            progname = b"binary\x00"
            str_addr = (sp_top - len(progname)) & ~0xF
            self.uc.mem_write(str_addr, progname)

            # Build the initial stack frame below the string
            frame  = q(1)         # argc = 1
            frame += q(str_addr)  # argv[0] = &"binary"
            frame += q(0)         # argv[1] = NULL
            frame += q(0)         # envp[0] = NULL
            frame += q(0)         # AT_NULL type
            frame += q(0)         # AT_NULL value

            sp = (str_addr - len(frame)) & ~0xF
            self.uc.mem_write(sp, frame)

            self.uc.reg_write(UC_X86_REG_RSP, sp)
            self.uc.reg_write(UC_X86_REG_RBP, sp)

        elif self.arch == "arm64":
            sp = sp_top & ~0xF
            self.uc.reg_write(UC_ARM64_REG_SP, sp)
            self.uc.reg_write(UC_ARM64_REG_X0, 1)   # argc

    def setup_heap(self):
        self.map_region(self.HEAP_BASE, self.HEAP_SIZE, "heap")

    # ── Register access ───────────────────────────

    def read_registers(self) -> Dict[str, int]:
        out = {}
        for name, reg_id in self._reg_map.items():
            try:
                out[name] = self.uc.reg_read(reg_id)
            except UcError:
                out[name] = 0
        return out

    def write_register(self, name: str, value: int) -> bool:
        reg_id = self._reg_map.get(name.lower())
        if reg_id is None:
            return False
        self.uc.reg_write(reg_id, value)
        return True

    def get_ip(self) -> int:
        if self.arch == "x86_64":
            return self.uc.reg_read(UC_X86_REG_RIP)
        return self.uc.reg_read(UC_ARM64_REG_PC)

    def set_ip(self, addr: int):
        if self.arch == "x86_64":
            self.uc.reg_write(UC_X86_REG_RIP, addr)
        else:
            self.uc.reg_write(UC_ARM64_REG_PC, addr)

    # ── Memory access ─────────────────────────────

    def read_memory(self, addr: int, size: int) -> bytes:
        try:
            return bytes(self.uc.mem_read(addr, size))
        except UcError as e:
            raise RuntimeError(f"Cannot read 0x{size:x} bytes @ 0x{addr:x}: {e}")

    def write_memory(self, addr: int, data: bytes) -> bool:
        try:
            self.uc.mem_write(addr, data)
            return True
        except UcError:
            return False

    def read_stack(self, depth: int = 16) -> List[Dict]:
        out = []
        rsp = self.uc.reg_read(UC_X86_REG_RSP if self.arch == "x86_64" else UC_ARM64_REG_SP)
        for i in range(depth):
            addr = rsp + i * 8
            try:
                raw = bytes(self.uc.mem_read(addr, 8))
                val = struct.unpack_from("<Q", raw)[0]
                out.append({
                    "offset": i, "addr": addr, "value": val,
                    "symbol": self.rev_symbols.get(val, ""),
                })
            except UcError:
                break
        return out

    # ── Breakpoints ───────────────────────────────

    def add_breakpoint(self, addr: int, condition: Optional[str] = None,
                       bp_type: str = "exec") -> Breakpoint:
        bp = Breakpoint(address=addr, condition=condition, bp_type=bp_type)
        if bp_type == "exec":
            self.breakpoints[addr] = bp
        else:
            self.watchpoints[addr] = bp
        return bp

    def remove_breakpoint(self, addr: int):
        self.breakpoints.pop(addr, None)
        self.watchpoints.pop(addr, None)

    def toggle_breakpoint(self, addr: int) -> bool:
        bp = self.breakpoints.get(addr) or self.watchpoints.get(addr)
        if bp:
            bp.enabled = not bp.enabled
            return bp.enabled
        return False

    def list_breakpoints(self) -> List[Dict]:
        out = []
        for bp in list(self.breakpoints.values()) + list(self.watchpoints.values()):
            out.append({
                "address":   bp.address,
                "enabled":   bp.enabled,
                "condition": bp.condition,
                "hit_count": bp.hit_count,
                "type":      bp.bp_type,
                "symbol":    self.rev_symbols.get(bp.address, ""),
            })
        return out

    # ── Hooks ─────────────────────────────────────

    def _eval_condition(self, cond: str, regs: Dict[str, int]) -> bool:
        try:
            return bool(eval(cond, {"__builtins__": {}}, regs))  # noqa: S307
        except Exception:
            return True

    def _on_insn(self, uc, address, size, user_data):
        self.current_ip = address

        # Read raw bytes for disassembly
        try:
            raw = bytes(uc.mem_read(address, size))
        except UcError:
            raw = b""

        # Import here to avoid circular import; cached by Python module system
        from analyzer import disassemble_bytes
        insns = disassemble_bytes(raw, address, self.arch)
        mnemonic = insns[0]["mnemonic"] if insns else "??"
        op_str   = insns[0]["op_str"]   if insns else ""

        self.insn_freq[mnemonic] = self.insn_freq.get(mnemonic, 0) + 1

        # Build trace entry
        entry = TraceEntry(
            address=address, mnemonic=mnemonic, op_str=op_str,
            registers=self.read_registers(),
            memory_reads=list(self._cur_reads),
            memory_writes=list(self._cur_writes),
        )
        self._cur_reads.clear()
        self._cur_writes.clear()

        # Syscall detection (x86-64)
        if mnemonic == "syscall" and self.arch == "x86_64":
            regs = entry.registers
            sc_num  = regs.get("rax", 0)
            sc_name = SYSCALL_TABLE_X64.get(sc_num, f"sys_{sc_num}")
            sc_info = {
                "address": address, "number": sc_num, "name": sc_name,
                "args": [regs.get(r, 0) for r in ("rdi","rsi","rdx","r10","r8","r9")],
            }
            entry.syscall = sc_info
            self.syscall_trace.append(sc_info)

        if len(self.trace) < self.max_trace:
            self.trace.append(entry)

        # Exec breakpoint
        bp = self.breakpoints.get(address)
        if bp and bp.enabled:
            if not bp.condition or self._eval_condition(bp.condition, entry.registers):
                bp.hit_count += 1
                logger.debug("Breakpoint hit @ 0x%x", address)
                uc.emu_stop()
                self._stopped = True

    def _on_mem_read(self, uc, access, address, size, value, user_data):
        self._cur_reads.append((address, size))
        key = address & ~0xF
        e = self.mem_heatmap.setdefault(key, [0, 0])
        e[0] += 1
        wp = self.watchpoints.get(address)
        if wp and wp.enabled and wp.bp_type in ("read", "access"):
            wp.hit_count += 1
            uc.emu_stop()
            self._stopped = True

    def _on_mem_write(self, uc, access, address, size, value, user_data):
        self._cur_writes.append((address, size, value))
        key = address & ~0xF
        e = self.mem_heatmap.setdefault(key, [0, 0])
        e[1] += 1
        # Capture ASCII strings written at runtime
        try:
            raw = struct.pack("<Q", value)[:size]
            if size >= 4 and all(32 <= b < 127 for b in raw):
                self.runtime_strings[address] = raw.decode("ascii", errors="replace")
        except Exception:
            pass
        wp = self.watchpoints.get(address)
        if wp and wp.enabled and wp.bp_type in ("write", "access"):
            wp.hit_count += 1
            uc.emu_stop()
            self._stopped = True

    def _on_unmapped_mem(self, uc, access, address, size, value, user_data):
        types = {UC_MEM_READ: "read", UC_MEM_WRITE: "write", UC_MEM_FETCH: "fetch"}
        logger.warning("Unmapped %s @ 0x%x", types.get(access, "??"), address)
        uc.emu_stop()
        self._stopped = True
        return False

    def _on_invalid_insn(self, uc, user_data):
        logger.warning("Invalid instruction @ 0x%x", self.get_ip())
        uc.emu_stop()
        self._stopped = True

    # ── Execution control ─────────────────────────

    def start(self, begin: int, until: int = 0xFFFFFFFFFFFFFFFF,
              timeout: int = 0, count: int = 0):
        self._stopped = False
        self._running = True
        self._step_mode = False
        try:
            self.uc.emu_start(begin, until, timeout=timeout, count=count)
        except UcError as e:
            logger.error("Emulation error: %s", e)
        finally:
            self._running = False

    def step(self, count: int = 1) -> Dict:
        self._stopped = False
        ip = self.get_ip()
        try:
            self.uc.emu_start(ip, 0xFFFFFFFFFFFFFFFF, count=count)
        except UcError as e:
            logger.warning("Step error: %s", e)
        return {
            "ip":        self.get_ip(),
            "registers": self.read_registers(),
            "stopped":   self._stopped,
        }

    def stop(self):
        try:
            self.uc.emu_stop()
        except UcError:
            pass
        self._running = False
        self._stopped = True

    def reset_trace(self):
        self.trace.clear()
        self.syscall_trace.clear()
        self.insn_freq.clear()
        self.mem_heatmap.clear()
        self.runtime_strings.clear()

    # ── Symbols ───────────────────────────────────

    def add_symbol(self, name: str, addr: int):
        self.symbols[name] = addr
        self.rev_symbols[addr] = name

    def resolve_symbol(self, name: str) -> Optional[int]:
        return self.symbols.get(name)

    # ── Serialisation helpers ─────────────────────

    def get_trace_json(self, start: int = 0, limit: int = 200) -> List[Dict]:
        out = []
        for e in self.trace[start: start + limit]:
            out.append({
                "address":    e.address,
                "mnemonic":   e.mnemonic,
                "op_str":     e.op_str,
                "registers":  dict(list(e.registers.items())[:8]),
                "mem_reads":  e.memory_reads,
                "mem_writes": [(a, s, v) for a, s, v in e.memory_writes],
                "syscall":    e.syscall,
                "symbol":     self.rev_symbols.get(e.address, ""),
            })
        return out

    def get_heatmap_json(self, top: int = 200) -> List[Dict]:
        items = sorted(self.mem_heatmap.items(),
                       key=lambda x: x[1][0] + x[1][1], reverse=True)
        return [{"addr": a, "reads": v[0], "writes": v[1]} for a, v in items[:top]]

    def get_state(self) -> Dict:
        return {
            "arch":      self.arch,
            "ip":        self.get_ip(),
            "registers": self.read_registers(),
            "running":   self._running,
            "stopped":   self._stopped,
            "trace_len": len(self.trace),
            "symbol":    self.rev_symbols.get(self.get_ip(), ""),
        }
