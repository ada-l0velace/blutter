"""Original Android ELF evidence for the source-backed ARM64 stub ABI contract."""
import struct

from elftools.elf.elffile import ELFFile

from binary_input import open_binary_input, read_exact
from runtime_evidence import MAX_LIBRARY_BYTES, MAX_PROGRAM_HEADERS

MAX_RELOCATIONS = 1_000_000
MAX_STUB_BYTES = 64 * 1024


def require(condition, message):
    if not condition:
        raise RuntimeError('Reader probe rejected: ' + message)


def packed_relative_relocations(data):
    """Decode the bounded Android APS2 RELA subset, following bionic's iterator."""
    require(data[:4] == b'APS2', 'unsupported Android relocation encoding')
    position = 4

    def pop():
        nonlocal position
        value = 0
        for shift in range(0, 70, 7):
            require(position < len(data), 'truncated packed relocation integer')
            byte = data[position]
            position += 1
            value |= (byte & 127) << shift
            if byte < 128:
                value = value - (1 << (shift + 7)) if byte & 64 else value
                require(-(1 << 63) <= value < 1 << 64, 'oversized packed relocation integer')
                return value
        raise RuntimeError('Reader probe rejected: oversized packed relocation integer')

    count, address = pop(), pop()
    require(0 < count <= MAX_RELOCATIONS and address >= 0, 'invalid packed relocation count or base')
    info = addend = seen = 0
    relative = {}
    addresses = set()
    while seen < count:
        length, flags = pop(), pop()
        require(0 < length <= count - seen and 0 <= flags <= 15 and
                not (flags & 4 and not flags & 8), 'invalid packed relocation group')
        delta = pop() if flags & 2 else 0
        if flags & 1:
            info = pop()
        mode = flags & 12
        if mode == 12:
            addend += pop()
        elif mode != 8:
            addend = 0
        for _ in range(length):
            address += delta if flags & 2 else pop()
            if not flags & 1:
                info = pop()
            if mode == 8:
                addend += pop()
            require(0 <= address < 1 << 64 and 0 <= info < 1 << 64 and
                    -(1 << 63) <= addend < 1 << 64, 'packed relocation arithmetic overflow')
            require(address not in addresses, 'duplicate packed relocation address')
            addresses.add(address)
            if info & 0xffffffff == 1027:  # R_AARCH64_RELATIVE
                require(info >> 32 == 0 and address % 8 == 0 and address not in relative,
                        'invalid or duplicate relative relocation')
                relative[address] = addend
            seen += 1
    require(position == len(data), 'unread packed relocation bytes')
    return relative


class OriginalElf:
    def __init__(self, path):
        with open_binary_input(path, 64, MAX_LIBRARY_BYTES) as (stream, size):
            elf = ELFFile(stream)
            require(elf.elfclass == 64 and elf.little_endian and elf['e_machine'] == 'EM_AARCH64',
                    'unsupported original stub ELF target')
            require(elf.num_segments() <= MAX_PROGRAM_HEADERS and elf.num_sections() <= 4096,
                    'excessive original stub ELF header count')
            stream.seek(0)
            self.data = read_exact(stream, size)
            self.loads = [dict(s.header) for s in elf.iter_segments() if s['p_type'] == 'PT_LOAD']
            for s in self.loads:
                require(s['p_offset'] <= size and s['p_filesz'] <= size - s['p_offset'] and
                        s['p_filesz'] <= s['p_memsz'] and s['p_vaddr'] < 1 << 64 and
                        s['p_memsz'] <= (1 << 64) - s['p_vaddr'], 'invalid original stub ELF segment')
            relocation = elf.get_section_by_name('.rela.dyn')
            self.relocation_bytes = None
            if relocation is not None:
                offset, length = relocation['sh_offset'], relocation['sh_size']
                require(offset <= size and length <= size - offset, 'unmapped packed relocation section')
                self.relocation_bytes = self.data[offset:offset + length]

    def read(self, address, length, executable=False):
        require(type(address) is int and type(length) is int and address >= 0 and
                0 <= length <= MAX_LIBRARY_BYTES, 'invalid original stub read')
        matches = [s for s in self.loads if s['p_vaddr'] <= address and
                   address + length <= s['p_vaddr'] + s['p_filesz'] and
                   (not executable or s['p_flags'] & 1)]
        require(len(matches) == 1, 'unmapped or ambiguous original stub extent')
        s = matches[0]
        offset = s['p_offset'] + address - s['p_vaddr']
        return self.data[offset:offset + length]

    def string_equals(self, address, name):
        try:
            return self.read(address, len(name) + 1) == name.encode('ascii') + b'\0'
        except RuntimeError:
            return False


def validate_engine_stub_table(engine, names):
    require(engine.relocation_bytes is not None, 'Android stub relocation section missing')
    pointers = packed_relative_relocations(engine.relocation_bytes)
    starts = [address for address, target in pointers.items() if engine.string_equals(target, names[0])]
    matches = []
    for address in starts:
        if all(address + index * 8 in pointers and
               engine.string_equals(pointers[address + index * 8], name)
               for index, name in enumerate(names)):
            engine.read(address, len(names) * 8)
            matches.append(address)
    require(len(matches) == 1, 'no unique relocated Android VM stub order')
    return matches[0]


# Register roles and order follow the pinned ARM64 source generators. Offsets
# come from the independently compiled reader, never from an application address.
RUNTIME = [('ldr', 24, 'call_to_runtime_stub'), ('str', 29, 'top_exit_frame_info'),
           ('str', 8, 'exit_through_ffi'), ('str', 5, 'vm_tag'),
           ('ldr', 28, 'write_barrier_mask'), ('ldr', 22, 'object_null'),
           ('ldr', 16, 'heap_base'), ('str', 2, 'vm_tag'),
           ('str', 31, 'exit_through_ffi'), ('str', 31, 'top_exit_frame_info'),
           ('ldr', 27, 'global_object_pool'), ('ldr', 21, 'dispatch_table_array')]
ARRAY = [('ldr', 0, 'top'), ('ldr', 16, 'end'), ('str', 7, 'top'),
         ('ldr', 5, 'AllocateArray'), ('ldr', 30, 'call_to_runtime_entry_point'),
         ('ldr', 16, 'EnsureRememberedAndMarkingDeferred'), ('str', 16, 'vm_tag'),
         ('str', 16, 'vm_tag'), ('ldr', 16, 'saved_stack_limit')]
NATIVE = [('str', 29, 'top_exit_frame_info'), ('str', 10, 'exit_through_ffi'),
          ('str', 9, 'vm_tag'), ('str', 10, 'execution_state'),
          ('ldr', 17, 'enter_safepoint_stub'), ('ldr', 17, 'exit_safepoint_stub'),
          ('str', 10, 'vm_tag'), ('str', 10, 'execution_state'),
          ('str', 31, 'top_exit_frame_info'), ('str', 10, 'exit_through_ffi')]


def contracts():
    result = {'CallToRuntime': RUNTIME, 'AllocateArray': ARRAY,
              'CallNativeThroughSafepoint': NATIVE}
    for name, role in [('CallBootstrapNative', 'bootstrap_native_wrapper_entry_point'),
                       ('CallNoScopeNative', 'no_scope_native_wrapper_entry_point'),
                       ('CallAutoScopeNative', 'auto_scope_native_wrapper_entry_point')]:
        result[name] = [('str', 29, 'top_exit_frame_info'), ('str', 6, 'exit_through_ffi'),
                        ('str', 5, 'vm_tag'), ('ldr', 30, role)] + RUNTIME[4:]
    return result


def thread_accesses(words):
    result = []
    for word in words:
        if word & 0x0a000000 == 0x08000000 and (word >> 5) & 31 == 26:
            opcode = word & 0xffc00000
            require(opcode in (0xf9400000, 0xf9000000), 'unsupported Thread access in ABI stub')
            result.append(('ldr' if opcode == 0xf9400000 else 'str', word & 31,
                           ((word >> 10) & 4095) * 8))
    return result


def validate_stub_abi(report, app, engine, ranges):
    offsets, stubs = report.get('thread_offsets'), report.get('stub_ranges')
    names = report['vm_stubs']
    require(isinstance(offsets, dict) and 1 <= len(offsets) <= 4096 and
            all(type(v) is int and 0 < v < 1 << 20 and v % 8 == 0 for v in offsets.values()),
            'invalid stub ABI Thread offsets')
    require(offsets.get('vm_tag') == report.get('vm_tag_offset') and
            type(report.get('native_call_state_offset')) is int and report['native_call_state_offset'] == 0,
            'stub ABI report offset disagreement')
    require(isinstance(stubs, list) and len(stubs) == len(names) and
            all(isinstance(s, dict) for s in stubs) and [s.get('name') for s in stubs] == names,
            'invalid ordered stub payload records')
    for stub in stubs:
        start, size = stub.get('start'), stub.get('size')
        require(type(start) is int and type(size) is int and 0 < size <= MAX_STUB_BYTES and
                start % 4 == 0 and size % 4 == 0 and ranges.get(start) == start + size,
                'stub payload disagrees with original native table')
    table = validate_engine_stub_table(engine, names)
    by_name = {s['name']: s for s in stubs}
    checked = 0
    for name, sequence in contracts().items():
        require(name in by_name, 'required ABI stub missing: ' + name)
        require(all(role in offsets for _, _, role in sequence), 'required ABI Thread role missing')
        stub = by_name[name]
        words = [v[0] for v in struct.iter_unpack('<I', app.read(stub['start'], stub['size'], executable=True))]
        expected = [(op, reg, offsets[role]) for op, reg, role in sequence]
        require(thread_accesses(words) == expected, 'Thread ABI sequence mismatch in ' + name)
        checked += len(expected)
        if name == 'CallNativeThroughSafepoint':
            require('safepoint_state' in offsets, 'safepoint role missing')
            # MOVZ X17, #state followed by ADD X17, X26, X17, twice.
            states = [((a >> 5) & 65535) for a, b in zip(words, words[1:])
                      if a & 0xffe0001f == 0xd2800011 and b == 0x8b110351]
            require(states == [offsets['safepoint_state']] * 2,
                    'safepoint ABI address construction mismatch')
    return {'abi_kind': 'arm64_stub_layout_v1', 'engine_stub_table': table,
            'abi_stubs_checked': len(contracts()), 'thread_accesses_checked': checked,
            'safepoint_addresses_checked': 2}
