"""Offline ARM64 guard observations, not snapshot-reader compatibility proofs."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import struct

from elftools.common.exceptions import ELFError
from elftools.elf.constants import P_FLAGS
from elftools.elf.elffile import ELFFile
from binary_input import EvidenceError, open_binary_input, read_exact

MAX_LIBRARY_BYTES = 256 * 1024 * 1024
MAX_CODE_BYTES = 128 * 1024 * 1024
MAX_PROGRAM_HEADERS = 256
MAX_GUARD_SITES = 8192
SCAN_CHUNK_BYTES = 64 * 1024
ADDRESS_SPACE_SIZE = 1 << 64
ELF64_HEADER_BYTES = 64
ELF64_PROGRAM_HEADER_BYTES = 56

LOAD_STORE_MASK = 0xffc00000
LDR_X_UNSIGNED = 0xf9400000
STR_X_UNSIGNED = 0xf9000000
CBZ_X_MASK = 0xff000000
CBZ_X = 0xb4000000
BRK_MASK = 0xffe0001f
BRK = 0xd4200000
BLR_MASK = 0xfffffc1f
BLR = 0xd63f0000
THREAD_REGISTER = 26
LEAF_GUARD_TRAP = 0xb12a
NATIVE_GUARD_TRAP = 0xb129
WORD = struct.Struct('<I')
GUARD_WORDS = struct.Struct('<4I')


class GuardStatus(Enum):
    NOT_OBSERVED = 'not_observed'
    PARTIAL = 'partial'
    CONSISTENT = 'consistent'
    CONFLICTING = 'conflicting'


class GuardKind(Enum):
    LEAF = 'leaf'
    NATIVE = 'native'


@dataclass(frozen=True)
class GuardOffsets:
    state: int
    vm_tag: int | None


@dataclass(frozen=True)
class GuardObservation:
    address: int
    offsets: GuardOffsets
    kind: GuardKind
    target_register: int


@dataclass(frozen=True)
class GuardEvidence:
    observations: tuple[GuardObservation, ...]
    bytes_scanned: int

    @property
    def status(self) -> GuardStatus:
        if not self.observations:
            return GuardStatus.NOT_OBSERVED
        states = {site.offsets.state for site in self.observations}
        tags = {site.offsets.vm_tag for site in self.observations if site.offsets.vm_tag is not None}
        if len(states) > 1 or len(tags) > 1:
            return GuardStatus.CONFLICTING
        if any(site.offsets.vm_tag is None for site in self.observations):
            return GuardStatus.PARTIAL
        return GuardStatus.CONSISTENT


@dataclass(frozen=True)
class _CodeSegment:
    file_offset: int
    address: int
    size: int
    memory_size: int


def _code_segments(stream, file_size):
    try:
        elf = ELFFile(stream)
        if elf.elfclass != 64 or not elf.little_endian or elf['e_machine'] != 'EM_AARCH64':
            raise EvidenceError('Guard collection requires a little-endian ARM64 ELF')
        if (elf['e_type'] not in ('ET_DYN', 'ET_EXEC') or elf['e_version'] != 'EV_CURRENT' or
                elf['e_ident']['EI_VERSION'] != 'EV_CURRENT'):
            raise EvidenceError('Unsupported ELF type or version')
        count, offset, entry_size = elf['e_phnum'], elf['e_phoff'], elf['e_phentsize']
        if (elf['e_ehsize'] != ELF64_HEADER_BYTES or entry_size != ELF64_PROGRAM_HEADER_BYTES or
                count > MAX_PROGRAM_HEADERS):
            raise EvidenceError('Unsupported ELF header sizes or program-header count')
        if (offset > file_size or count * entry_size > file_size - offset or
                count and offset < ELF64_HEADER_BYTES):
            raise EvidenceError('Program headers lie outside the ELF input')
        stream.seek(offset)
        headers = [elf.structs.Elf_Phdr.parse(read_exact(stream, entry_size)) for _ in range(count)]
    except ELFError as error:
        raise EvidenceError('Invalid ELF input') from error

    segments = []
    code_bytes = 0
    for header in headers:
        if header['p_type'] != 'PT_LOAD':
            continue
        start, size = header['p_offset'], header['p_filesz']
        address, memory_size, alignment = header['p_vaddr'], header['p_memsz'], header['p_align']
        if start > file_size or size > file_size - start or size > memory_size:
            raise EvidenceError('Load segment exceeds the ELF input or its memory extent')
        if memory_size > ADDRESS_SPACE_SIZE - address:
            raise EvidenceError('Load segment exceeds the ELF address space')
        if alignment > 1 and (alignment & (alignment - 1) or start % alignment != address % alignment):
            raise EvidenceError('Invalid load-segment alignment')
        if header['p_flags'] & P_FLAGS.PF_X and size:
            if address % 4:
                raise EvidenceError('Unaligned executable segment')
            code_bytes += size
            if code_bytes > MAX_CODE_BYTES:
                raise EvidenceError('Executable input exceeds the guard scan limit')
            segments.append(_CodeSegment(start, address, size, memory_size))

    segments.sort(key=lambda segment: segment.address)
    for previous, current in zip(segments, segments[1:]):
        if previous.address + previous.memory_size > current.address:
            raise EvidenceError('Overlapping executable address ranges')
    by_file = sorted(segments, key=lambda segment: segment.file_offset)
    for previous, current in zip(by_file, by_file[1:]):
        if previous.file_offset + previous.size > current.file_offset:
            raise EvidenceError('Overlapping executable file ranges')
    return segments, code_bytes


def _guard_at(data, offset, address):
    if WORD.unpack_from(data, offset + 8)[0] & BRK_MASK != BRK:
        return None
    load, branch, trap, call = GUARD_WORDS.unpack_from(data, offset)
    if load & LOAD_STORE_MASK != LDR_X_UNSIGNED or (load >> 5) & 31 != THREAD_REGISTER:
        return None
    scratch = load & 31
    if branch & CBZ_X_MASK != CBZ_X or branch & 31 != scratch:
        return None
    # CBZ is relative to itself; +8 must land on the BLR.
    if (branch >> 5) & 0x7ffff != 2 or call & BLR_MASK != BLR:
        return None
    trap_id, target = (trap >> 5) & 0xffff, (call >> 5) & 31
    if scratch == 17 and trap_id == LEAF_GUARD_TRAP and target == 16:
        kind = GuardKind.LEAF
    elif scratch == 16 and trap_id == NATIVE_GUARD_TRAP and target not in (16, THREAD_REGISTER, 31):
        kind = GuardKind.NATIVE
    else:
        return None
    tag = None
    if offset >= 4:
        store = WORD.unpack_from(data, offset - 4)[0]
        if store & LOAD_STORE_MASK == STR_X_UNSIGNED and (store >> 5) & 31 == THREAD_REGISTER and store & 31 == target:
            tag = ((store >> 10) & 0xfff) * 8
    return GuardObservation(address, GuardOffsets(((load >> 10) & 0xfff) * 8, tag), kind, target)


def _scan_segment(stream, segment, observations):
    stream.seek(segment.file_offset)
    consumed = 0
    carry = b''
    next_address = segment.address
    while consumed < segment.size:
        chunk = read_exact(stream, min(SCAN_CHUNK_BYTES, segment.size - consumed))
        data = carry + chunk
        address = segment.address + consumed - len(carry)
        for offset in range(next_address - address, len(data) - 15, 4):
            next_address = address + offset + 4
            site = _guard_at(data, offset, address + offset)
            if site is not None:
                if len(observations) >= MAX_GUARD_SITES:
                    raise EvidenceError('Guard observations exceed the input limit')
                observations.append(site)
        consumed += len(chunk)
        carry = data[-16:]


def collect_guard_evidence(path) -> GuardEvidence:
    """Read instruction candidates only; no match does not prove a guard absent."""
    with open_binary_input(path, ELF64_HEADER_BYTES, MAX_LIBRARY_BYTES) as (stream, size):
        segments, code_bytes = _code_segments(stream, size)
        observations = []
        for segment in segments:
            _scan_segment(stream, segment, observations)
    return GuardEvidence(tuple(observations), code_bytes)
