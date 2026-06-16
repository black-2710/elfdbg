"""
emulator.py - Unicorn Engine wrapper with hooks, breakpoints, and state management.
Supports x86-64 and ARM64 ELF binaries, including dynamically linked / PIE.
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
# Fault sentinel – RIP values that mean "crashed"
# ──────────────────────────────────────────────
FAULTED_IP_THRESHOLD = 0x10000   # anything below this is a NULL/near-null fault

# ──────────────────────────────────────────────
# Data structures
# ──────────────────────────────────────────────

@dataclass
class Breakpoint:
    address: int
    enabled: bool = True
    condition: Optional[str] = None
    hit_count: int = 0
    bp_type: str = "exec"


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

SYSCALL_TABLE_X64 = {
    0:"read", 1:"write", 2:"open", 3:"close",
    4:"stat", 5:"fstat", 6:"lstat", 9:"mmap",
    10:"mprotect", 11:"munmap", 12:"brk",
    20:"writev", 21:"access", 39:"getpid",
    57:"fork", 59:"execve", 60:"exit",
    63:"uname", 102:"getuid", 231:"exit_group",
}


# ──────────────────────────────────────────────
# ELFEmulator
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

        # PLT stub → symbol name mapping (for dynamic binaries)
        self.plt_stubs: Dict[int, str] = {}   # stub_addr -> symbol_name
        self.plt_calls: List[Dict]     = []   # log of intercepted PLT calls

        self._running   = False
        self._stopped   = False
        self._faulted   = False   # True when RIP is at an invalid address
        self._lock      = threading.Lock()

        self._cur_reads:  List[Tuple[int, int]]      = []
        self._cur_writes: List[Tuple[int, int, int]] = []

        self.mem_heatmap:     Dict[int, List[int]] = {}
        self.insn_freq:       Dict[str, int]       = {}
        self.syscall_trace:   List[Dict]           = []
        self.runtime_strings: Dict[int, str]       = {}

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
        self._faulted = False
        self._install_hooks()
        logger.info("Unicorn initialised for %s", self.arch)

    def _install_hooks(self):
        uc = self.uc
        uc.hook_add(UC_HOOK_CODE,               self._on_insn)
        uc.hook_add(UC_HOOK_MEM_READ,           self._on_mem_read)
        uc.hook_add(UC_HOOK_MEM_WRITE,          self._on_mem_write)
        uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED,  self._on_unmapped_mem)
        uc.hook_add(UC_HOOK_MEM_WRITE_UNMAPPED, self._on_unmapped_mem)
        uc.hook_add(UC_HOOK_MEM_FETCH_UNMAPPED, self._on_unmapped_mem)
        uc.hook_add(UC_HOOK_INSN_INVALID,       self._on_invalid_insn)

    # ── Memory management ─────────────────────────

    def map_region(self, base: int, size: int, label: str,
                   perms: int = UC_PROT_ALL, data: bytes = b""):
        page_base = base & ~0xFFF
        offset    = base - page_base
        aligned   = ((offset + size + 0xFFF) >> 12) << 12
        if aligned == 0:
            aligned = 0x1000
        try:
            self.uc.mem_map(page_base, aligned, perms)
        except UcError:
            pass
        if data:
            try:
                self.uc.mem_write(base, data)
            except UcError as e:
                logger.warning("mem_write @ 0x%x failed: %s", base, e)
        self.regions.append(MemoryRegion(page_base, aligned, perms, label))
        logger.debug("Mapped %s @ 0x%x size=0x%x", label, page_base, aligned)

    def setup_stack(self):
        """Build ABI-compliant x86-64 / AArch64 initial stack."""
        self.map_region(self.STACK_BASE, self.STACK_SIZE, "stack")
        sp_top = self.STACK_BASE + self.STACK_SIZE - 0x200

        if self.arch == "x86_64":
            def q(v): return struct.pack("<Q", v & 0xFFFFFFFFFFFFFFFF)
            progname = b"binary\x00"
            str_addr = (sp_top - len(progname)) & ~0xF
            self.uc.mem_write(str_addr, progname)
            frame  = q(1)         # argc = 1
            frame += q(str_addr)  # argv[0]
            frame += q(0)         # argv NULL
            frame += q(0)         # envp NULL
            frame += q(0)         # AT_NULL type
            frame += q(0)         # AT_NULL value
            sp = (str_addr - len(frame)) & ~0xF
            self.uc.mem_write(sp, frame)
            self.uc.reg_write(UC_X86_REG_RSP, sp)
            self.uc.reg_write(UC_X86_REG_RBP, sp)
        elif self.arch == "arm64":
            sp = sp_top & ~0xF
            self.uc.reg_write(UC_ARM64_REG_SP, sp)
            self.uc.reg_write(UC_ARM64_REG_X0, 1)

    def setup_heap(self):
        self.map_region(self.HEAP_BASE, self.HEAP_SIZE, "heap")

    def install_plt_stub(self, got_addr: int, sym_name: str) -> int:
        """
        Write a 4-byte returning stub into the PLT stub page and point the
        GOT entry at it.  The stub does:
            xor rax, rax   ; return value = 0
            ret            ; return to caller
        Returns the stub address.
        """
        STUB_PAGE = 0x0F000000
        STUB_SIZE = 4   # bytes per stub

        # Ensure stub page exists
        if not any(r.label == "plt_stubs" for r in self.regions):
            stub_bytes = (b"\x48\x31\xc0\xc3") * (0x1000 // STUB_SIZE)
            self.map_region(STUB_PAGE, 0x1000, "plt_stubs",
                            UC_PROT_READ | UC_PROT_EXEC, stub_bytes)

        idx = len(self.plt_stubs)
        stub_addr = STUB_PAGE + idx * STUB_SIZE
        if stub_addr + STUB_SIZE > STUB_PAGE + 0x1000:
            logger.warning("PLT stub page full, reusing last slot")
            stub_addr = STUB_PAGE + (0x1000 - STUB_SIZE)

        # Point GOT entry → stub
        self.write_memory(got_addr, struct.pack("<Q", stub_addr))
        # Register for symbol resolution and PLT call interception
        self.plt_stubs[stub_addr] = sym_name
        self.add_symbol(f"plt_{sym_name}", stub_addr)
        return stub_addr

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

    def is_faulted(self) -> bool:
        """True if RIP is stuck at a known-bad address."""
        ip = self.get_ip()
        return self._faulted or ip < FAULTED_IP_THRESHOLD

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
                out.append({"offset": i, "addr": addr, "value": val,
                            "symbol": self.rev_symbols.get(val, "")})
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
                "address":   bp.address, "enabled": bp.enabled,
                "condition": bp.condition, "hit_count": bp.hit_count,
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

        try:
            raw = bytes(uc.mem_read(address, size))
        except UcError:
            raw = b""

        from analyzer import disassemble_bytes
        insns    = disassemble_bytes(raw, address, self.arch)
        mnemonic = insns[0]["mnemonic"] if insns else "??"
        op_str   = insns[0]["op_str"]   if insns else ""

        self.insn_freq[mnemonic] = self.insn_freq.get(mnemonic, 0) + 1

        # Intercept PLT stub calls – log and let the stub's `ret` return naturally
        if address in self.plt_stubs:
            sym = self.plt_stubs[address]
            regs = self.read_registers()
            call_info = {
                "address":  address,
                "symbol":   sym,
                "args":     [regs.get(r, 0) for r in ("rdi","rsi","rdx","rcx","r8","r9")],
            }
            self.plt_calls.append(call_info)
            # Add to syscall_trace so UI can show PLT calls alongside syscalls
            self.syscall_trace.append({
                "address": address, "number": -1,
                "name": f"plt:{sym}",
                "args": call_info["args"],
            })
            logger.debug("PLT call: %s @ 0x%x", sym, address)
            # Do NOT stop; let the stub's `ret` continue execution normally

        entry = TraceEntry(
            address=address, mnemonic=mnemonic, op_str=op_str,
            registers=self.read_registers(),
            memory_reads=list(self._cur_reads),
            memory_writes=list(self._cur_writes),
        )
        self._cur_reads.clear()
        self._cur_writes.clear()

        # Syscall detection
        if mnemonic == "syscall" and self.arch == "x86_64":
            regs    = entry.registers
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

        # Exec breakpoints
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
        types = {UC_MEM_READ:"read", UC_MEM_WRITE:"write", UC_MEM_FETCH:"fetch"}
        kind = types.get(access, "??")
        logger.warning("Unmapped %s @ 0x%x", kind, address)
        if kind == "fetch":
            self._faulted = True
        uc.emu_stop()
        self._stopped = True
        return False

    def _on_invalid_insn(self, uc, user_data):
        ip = self.get_ip()
        logger.warning("Invalid instruction @ 0x%x", ip)
        uc.emu_stop()
        self._stopped = True

    # ── Execution control ─────────────────────────

    def start(self, begin: int, until: int = 0xFFFFFFFFFFFFFFFF,
              timeout: int = 0, count: int = 0):
        if self.is_faulted():
            logger.warning("Cannot start: emulator is in faulted state (RIP=0x%x). Reset first.", self.get_ip())
            return
        self._stopped = False
        self._running = True
        try:
            self.uc.emu_start(begin, until, timeout=timeout, count=count)
        except UcError as e:
            logger.error("Emulation error: %s", e)
            self._faulted = True
        finally:
            self._running = False

    def step(self, count: int = 1) -> Dict:
        ip = self.get_ip()
        if self.is_faulted():
            logger.warning("Cannot step: faulted state RIP=0x%x. Reset to continue.", ip)
            return {
                "ip": ip, "registers": self.read_registers(),
                "stopped": True, "faulted": True,
                "error": f"Emulator faulted at 0x{ip:x} — press Reset to restart",
            }
        self._stopped = False
        try:
            self.uc.emu_start(ip, 0xFFFFFFFFFFFFFFFF, count=count)
        except UcError as e:
            logger.warning("Step error: %s", e)
            self._faulted = True
        return {
            "ip":        self.get_ip(),
            "registers": self.read_registers(),
            "stopped":   self._stopped,
            "faulted":   self.is_faulted(),
            "plt_calls": self.plt_calls[-10:],
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
        self.plt_calls.clear()

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
                       key=lambda x: x[1][0]+x[1][1], reverse=True)
        return [{"addr": a, "reads": v[0], "writes": v[1]} for a, v in items[:top]]

    def get_state(self) -> Dict:
        ip = self.get_ip()
        return {
            "arch":      self.arch,
            "ip":        ip,
            "registers": self.read_registers(),
            "running":   self._running,
            "stopped":   self._stopped,
            "faulted":   self.is_faulted(),
            "trace_len": len(self.trace),
            "symbol":    self.rev_symbols.get(ip, ""),
            "plt_calls": self.plt_calls[-5:],
        }
