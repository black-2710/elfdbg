"""
analyzer.py - ELF parsing, Capstone disassembly, symbol resolution,
              trace analysis, function detection, and string extraction.
"""

import logging
import struct
from typing import Any, Dict, List, Optional, Tuple

from capstone import (
    CS_ARCH_ARM64, CS_ARCH_X86,
    CS_MODE_64, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN,
    Cs, CsError,
)
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from elftools.elf.relocation import RelocationSection
from elftools.elf.dynamic import DynamicSection

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────
# Disassembly helpers
# ──────────────────────────────────────────────

def _get_cs(arch: str) -> Cs:
    if arch == "x86_64":
        cs = Cs(CS_ARCH_X86, CS_MODE_64)
    elif arch == "arm64":
        cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)
    else:
        raise ValueError(f"Unsupported arch: {arch}")
    cs.detail = True
    return cs


def disassemble_bytes(data: bytes, base_addr: int, arch: str = "x86_64",
                      max_insns: int = 0) -> List[Dict]:
    cs  = _get_cs(arch)
    out = []
    for insn in cs.disasm(data, base_addr):
        out.append({
            "address":  insn.address,
            "mnemonic": insn.mnemonic,
            "op_str":   insn.op_str,
            "bytes":    insn.bytes.hex(),
            "size":     insn.size,
        })
        if max_insns and len(out) >= max_insns:
            break
    return out


def disassemble_region(data: bytes, base_addr: int, arch: str = "x86_64",
                       max_insns: int = 500) -> List[Dict]:
    raw = disassemble_bytes(data, base_addr, arch, max_insns)
    targets = set()
    for ins in raw:
        if ins["op_str"].startswith("0x"):
            try:
                targets.add(int(ins["op_str"], 16))
            except ValueError:
                pass
    for ins in raw:
        ins["is_branch_target"] = ins["address"] in targets
    return raw


# ──────────────────────────────────────────────
# ELF parser
# ──────────────────────────────────────────────

class ELFAnalyzer:
    def __init__(self, data: bytes):
        import io
        self._data   = data
        self._stream = io.BytesIO(data)
        self.elf     = ELFFile(self._stream)
        self.arch    = self._detect_arch()
        self.is_dynamic = (self.elf.header.e_type == "ET_DYN") or self._has_dynamic_section()
        self.sections:    List[Dict] = []
        self.segments:    List[Dict] = []
        self.symbols:     Dict[str, int] = {}
        self.imports:     List[str] = []
        self.exports:     List[Dict] = []
        self.strings:     List[Dict] = []
        self.relocations: List[Dict] = []
        self.entry_point  = self.elf.header.e_entry
        self._parse()

    def _detect_arch(self) -> str:
        m = self.elf.header.e_machine
        if m == "EM_X86_64":  return "x86_64"
        if m == "EM_AARCH64": return "arm64"
        raise ValueError(f"Unsupported ELF machine: {m}")

    def _has_dynamic_section(self) -> bool:
        for sec in self.elf.iter_sections():
            if isinstance(sec, DynamicSection):
                return True
        return False

    def _parse(self):
        self._parse_sections()
        self._parse_segments()
        self._parse_symbols()
        self._parse_strings()
        self._parse_relocations()

    def _parse_sections(self):
        for sec in self.elf.iter_sections():
            self.sections.append({
                "name":    sec.name,
                "type":    sec.header.sh_type,
                "addr":    sec.header.sh_addr,
                "offset":  sec.header.sh_offset,
                "size":    sec.header.sh_size,
                "flags":   sec.header.sh_flags,
                "entsize": sec.header.sh_entsize,
            })

    def _parse_segments(self):
        for seg in self.elf.iter_segments():
            self.segments.append({
                "type":   seg.header.p_type,
                "vaddr":  seg.header.p_vaddr,
                "paddr":  seg.header.p_paddr,
                "filesz": seg.header.p_filesz,
                "memsz":  seg.header.p_memsz,
                "flags":  seg.header.p_flags,
                "align":  seg.header.p_align,
            })

    def _parse_symbols(self):
        for sec in self.elf.iter_sections():
            if not isinstance(sec, SymbolTableSection):
                continue
            for sym in sec.iter_symbols():
                if sym.name and sym.entry.st_value:
                    self.symbols[sym.name] = sym.entry.st_value
                info = sym.entry.st_info
                entry = {
                    "name":    sym.name,
                    "address": sym.entry.st_value,
                    "size":    sym.entry.st_size,
                    "bind":    info.bind,
                    "type":    info.type,
                }
                if info.bind == "STB_GLOBAL" and info.type == "STT_FUNC" and sym.entry.st_value:
                    self.exports.append(entry)
                elif info.bind == "STB_GLOBAL" and sym.entry.st_value == 0:
                    self.imports.append(sym.name)

    def _parse_strings(self):
        for sec in self.elf.iter_sections():
            if sec.name not in (".rodata", ".data", ".text"):
                continue
            data = sec.data()
            addr = sec.header.sh_addr
            i = 0
            while i < len(data):
                j = i
                while j < len(data) and 32 <= data[j] < 127:
                    j += 1
                if j - i >= 4:
                    self.strings.append({
                        "address": addr + i,
                        "value":   data[i:j].decode("ascii", errors="replace"),
                        "section": sec.name,
                    })
                i = max(j, i + 1)

    def _parse_relocations(self):
        for sec in self.elf.iter_sections():
            if not isinstance(sec, RelocationSection):
                continue
            sym_table = self.elf.get_section(sec.header.sh_link)
            for rel in sec.iter_relocations():
                sym_name = ""
                if rel.entry.r_info_sym and sym_table:
                    sym = sym_table.get_symbol(rel.entry.r_info_sym)
                    if sym:
                        sym_name = sym.name
                self.relocations.append({
                    "offset": rel.entry.r_offset,
                    "type":   rel.entry.r_info_type,
                    "symbol": sym_name,
                    "addend": rel.entry.get("r_addend", 0),
                })

    def get_section_data(self, name: str) -> Tuple[Optional[bytes], int]:
        for sec in self.elf.iter_sections():
            if sec.name == name:
                return sec.data(), sec.header.sh_addr
        return None, 0

    def disassemble_text(self, max_insns: int = 1000) -> List[Dict]:
        data, addr = self.get_section_data(".text")
        if data is None:
            return []
        return disassemble_region(data, addr, self.arch, max_insns)

    def disassemble_at(self, addr: int, size: int, emulator=None) -> List[Dict]:
        if emulator and emulator.uc:
            try:
                data = bytes(emulator.uc.mem_read(addr, size))
            except Exception:
                data = self._read_file_bytes(addr, size)
        else:
            data = self._read_file_bytes(addr, size)
        return disassemble_region(data, addr, self.arch)

    def _read_file_bytes(self, vaddr: int, size: int) -> bytes:
        for seg in self.elf.iter_segments():
            v = seg.header.p_vaddr
            f = seg.header.p_offset
            s = seg.header.p_filesz
            if v <= vaddr < v + s:
                offset = f + (vaddr - v)
                self._stream.seek(offset)
                return self._stream.read(size)
        return b"\xcc" * size

    def detect_functions(self) -> List[Dict]:
        funcs   = []
        seen    = set(self.symbols.values())
        data, base = self.get_section_data(".text")
        if data is None:
            return []
        if self.arch == "x86_64":
            pattern = b"\x55\x48\x89\xe5"
            i = 0
            while True:
                idx = data.find(pattern, i)
                if idx == -1:
                    break
                addr = base + idx
                if addr not in seen:
                    seen.add(addr)
                    name = self.symbols_rev().get(addr, f"sub_{addr:x}")
                    funcs.append({"address": addr, "name": name, "confidence": "high"})
                i = idx + 1
        return funcs

    def symbols_rev(self) -> Dict[int, str]:
        return {v: k for k, v in self.symbols.items()}

    def summary(self) -> Dict:
        hdr = self.elf.header
        return {
            "arch":         self.arch,
            "machine":      hdr.e_machine,
            "type":         hdr.e_type,
            "entry_point":  hdr.e_entry,
            "class":        self.elf.elfclass,
            "encoding":     "LSB" if self.elf.little_endian else "MSB",
            "num_sections": len(self.sections),
            "num_segments": len(self.segments),
            "num_symbols":  len(self.symbols),
            "num_imports":  len(self.imports),
            "num_exports":  len(self.exports),
            "num_strings":  len(self.strings),
            "file_size":    len(self._data),
            "is_dynamic":   self.is_dynamic,
            "is_pie":       self.elf.header.e_type == "ET_DYN",
        }

    def load_into_emulator(self, emu) -> bool:
        """
        Smart loader: automatically uses dynamic loader for ET_DYN / dynamically
        linked binaries, and the simple loader for static ET_EXEC binaries.
        """
        if self.is_dynamic:
            logger.info("Detected dynamic/PIE binary — using dynamic loader")
            load_dynamic_into_emulator(self, emu)
            return True

        # ── Static ET_EXEC loader ──
        from unicorn import UC_PROT_ALL, UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC
        emu.init(self.arch)
        for seg in self.elf.iter_segments():
            if seg.header.p_type != "PT_LOAD":
                continue
            vaddr  = seg.header.p_vaddr
            memsz  = seg.header.p_memsz
            data   = seg.data()
            flags  = seg.header.p_flags
            perms  = 0
            if flags & 0x4: perms |= UC_PROT_READ
            if flags & 0x2: perms |= UC_PROT_WRITE
            if flags & 0x1: perms |= UC_PROT_EXEC
            if perms == 0:  perms = UC_PROT_ALL
            emu.map_region(vaddr, memsz, f"load_{vaddr:x}", perms, data)

        emu.setup_stack()
        emu.setup_heap()
        emu.entry_point = self.entry_point
        emu.set_ip(self.entry_point)
        for name, addr in self.symbols.items():
            emu.add_symbol(name, addr)
        logger.info("Loaded static ELF @ entry=0x%x", self.entry_point)
        return True


# ──────────────────────────────────────────────
# Trace analysis utilities
# ──────────────────────────────────────────────

def analyse_trace(trace_entries: List[Dict]) -> Dict:
    if not trace_entries:
        return {}
    freq: Dict[str, int] = {}
    syscalls: List[Dict] = []
    mem_writes = mem_reads = 0
    for e in trace_entries:
        freq[e["mnemonic"]] = freq.get(e["mnemonic"], 0) + 1
        mem_reads  += len(e.get("mem_reads",  []))
        mem_writes += len(e.get("mem_writes", []))
        if e.get("syscall"):
            syscalls.append(e["syscall"])
    top_insns = sorted(freq.items(), key=lambda x: x[1], reverse=True)[:20]
    return {
        "total_instructions": len(trace_entries),
        "unique_mnemonics":   len(freq),
        "top_instructions":   [{"mnemonic": m, "count": c} for m, c in top_insns],
        "memory_reads":       mem_reads,
        "memory_writes":      mem_writes,
        "syscall_count":      len(syscalls),
        "syscalls":           syscalls,
    }


def extract_strings_from_trace(trace_entries: List[Dict]) -> List[Dict]:
    results = []
    for e in trace_entries:
        for addr, size, val in e.get("mem_writes", []):
            if size >= 4:
                raw = struct.pack("<Q", val)[:size]
                if all(32 <= b < 127 for b in raw):
                    results.append({
                        "address":          addr,
                        "value":            raw.decode("ascii", errors="replace"),
                        "instruction_addr": e["address"],
                    })
    return results


# ──────────────────────────────────────────────────────────────────────────────
# Dynamic / PIE binary loader
# ──────────────────────────────────────────────────────────────────────────────

STUB_PAGE_BASE = 0x0F000000
# Each stub: xor rax,rax (3 bytes) + ret (1 byte) = 4 bytes
# This returns 0 (success) to the caller and resumes execution normally.
STUB_BYTES = b"\x48\x31\xc0\xc3"   # xor rax,rax ; ret
STUB_SIZE  = len(STUB_BYTES)        # 4


def load_dynamic_into_emulator(analyzer: ELFAnalyzer, emu,
                                load_base: int = 0x400000) -> Dict:
    """
    Load a dynamically linked or PIE ELF into the emulator:
      1. Detect PIE (ET_DYN) and choose load_base
      2. Map all PT_LOAD segments offset by load_base
      3. Apply R_RELATIVE relocations
      4. Stub JUMP_SLOT / GLOB_DAT GOT entries with `xor rax,rax; ret`
         so PLT calls return 0 gracefully instead of jumping to 0x0
      5. Set up stack, heap, entry point
    """
    from unicorn import UC_PROT_ALL, UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC
    import struct as _s

    is_pie = analyzer.elf.header.e_type == "ET_DYN"
    base   = load_base if is_pie else 0

    emu.init(analyzer.arch)

    # ── 1. Map PT_LOAD segments ──
    for seg in analyzer.elf.iter_segments():
        if seg.header.p_type != "PT_LOAD":
            continue
        vaddr = seg.header.p_vaddr + base
        memsz = seg.header.p_memsz
        data  = seg.data()
        flags = seg.header.p_flags
        perms = 0
        if flags & 0x4: perms |= UC_PROT_READ
        if flags & 0x2: perms |= UC_PROT_WRITE
        if flags & 0x1: perms |= UC_PROT_EXEC
        if perms == 0:  perms = UC_PROT_ALL
        emu.map_region(vaddr, memsz, f"seg_{vaddr:x}", perms, data)

    # ── 2. Map PLT stub page (filled with `xor rax,rax; ret` stubs) ──
    max_stubs   = 0x1000 // STUB_SIZE
    stub_page   = STUB_BYTES * max_stubs
    emu.map_region(STUB_PAGE_BASE, 0x1000, "plt_stubs",
                   UC_PROT_READ | UC_PROT_EXEC, stub_page)

    # ── 3. Apply relocations ──
    relocs_applied = 0
    stubs: Dict[str, int] = {}
    stub_idx = 0

    from elftools.elf.relocation import RelocationSection

    for sec in analyzer.elf.iter_sections():
        if not isinstance(sec, RelocationSection):
            continue
        sym_table = analyzer.elf.get_section(sec.header.sh_link)
        for rel in sec.iter_relocations():
            r_offset = rel.entry.r_offset + base
            r_type   = rel.entry.r_info_type
            r_addend = rel.entry.get("r_addend", 0)
            sym_name = ""
            if rel.entry.r_info_sym and sym_table:
                sym = sym_table.get_symbol(rel.entry.r_info_sym)
                if sym:
                    sym_name = sym.name

            if r_type == 8:
                # R_X86_64_RELATIVE: *GOT = load_base + addend
                val = _s.pack("<Q", (base + r_addend) & 0xFFFFFFFFFFFFFFFF)
                emu.write_memory(r_offset, val)
                relocs_applied += 1

            elif r_type in (6, 7) and sym_name:
                # R_JUMP_SLOT / R_GLOB_DAT: point GOT → unique stub slot
                if stub_idx < max_stubs:
                    stub_addr = STUB_PAGE_BASE + stub_idx * STUB_SIZE
                    val = _s.pack("<Q", stub_addr)
                    emu.write_memory(r_offset, val)
                    # Register in emulator's PLT table
                    emu.plt_stubs[stub_addr] = sym_name
                    emu.add_symbol(f"plt_{sym_name}", stub_addr)
                    stubs[sym_name] = stub_addr
                    stub_idx += 1
                    relocs_applied += 1
                    logger.debug("Stubbed %s @ GOT=0x%x → stub=0x%x",
                                 sym_name, r_offset, stub_addr)

            elif r_type == 1:
                relocs_applied += 1   # R_ABS64, skip without full sym resolution

    # ── 4. Stack, heap, entry point ──
    emu.setup_stack()
    emu.setup_heap()
    emu.entry_point = analyzer.entry_point + base
    emu.set_ip(emu.entry_point)

    for name, addr in analyzer.symbols.items():
        emu.add_symbol(name, addr + base if is_pie else addr)

    logger.info("Dynamic load: base=0x%x entry=0x%x relocs=%d stubs=%d",
                base, emu.entry_point, relocs_applied, len(stubs))

    return {
        "load_base":      base,
        "entry_point":    emu.entry_point,
        "relocs_applied": relocs_applied,
        "stubs":          stubs,
        "is_pie":         is_pie,
        "is_dynamic":     True,
    }
