#!/usr/bin/env python3
"""Verify exported native payloads against records/bytes in the original ELF.

This checks code boundaries and raw assembly, not Dart semantics or type recovery.
"""
import argparse
import ast
import bisect
import hashlib
import json
import re
import struct
import warnings
from pathlib import Path

import capstone
from elftools.elf.elffile import ELFFile
from check_blutter_output import unprivileged_load_mnemonic


def main():
    if not __debug__:
        raise RuntimeError('Coverage checks require assertions; run Python without optimization')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('libapp', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--vm-audit', type=Path)
    args = parser.parse_args()
    raw = args.libapp.read_bytes()
    with args.libapp.open('rb') as stream:
        elf = ELFFile(stream)
        assert elf['e_machine'] == 'EM_AARCH64'
        segments = [(p['p_vaddr'], p['p_filesz'], p['p_offset'])
                    for p in elf.iter_segments() if p['p_type'] == 'PT_LOAD']
        symbols = elf.get_section_by_name('.dynsym')
        selected = (symbols.get_symbol_by_name('_kDartSnapshotText') or
                    symbols.get_symbol_by_name('_kDartIsolateSnapshotInstructions'))
        assert selected, 'No supported instructions-image symbol'
        symbol = selected[0]
        image_start, symbol_size = symbol['st_value'], symbol['st_size']
        vm_symbols = symbols.get_symbol_by_name('_kDartVmSnapshotInstructions') or []
        vm_image = ((vm_symbols[0]['st_value'], vm_symbols[0]['st_size']) if vm_symbols else None)
        selected_data = (symbols.get_symbol_by_name('_kDartSnapshotData') or
                         symbols.get_symbol_by_name('_kDartIsolateSnapshotData'))
        assert selected_data, 'No supported snapshot-data symbol'
        data_address, data_size = selected_data[0]['st_value'], selected_data[0]['st_size']

    def read(address, size):
        assert size >= 0
        for base, length, offset in segments:
            if base <= address and address + size <= base + length:
                pos = offset + address - base
                return raw[pos:pos + size]
        raise AssertionError(f'Unmapped ELF span {address:#x}+{size:#x}')

    image_size = struct.unpack('<Q', read(image_start, 8))[0]
    section_offset = struct.unpack('<Q', read(image_start + 8, 8))[0]
    assert section_offset == 64
    assert image_size == symbol_size
    image_end = image_start + image_size
    manifest = json.loads((args.output / 'snapshot_code.json').read_text())
    assert (manifest['image_start'], manifest['image_end']) == (image_start, image_end)
    table_address = manifest['table_data_address']
    # Locate the table independently from the modern five-field snapshot header.
    # Do not trust a producer-selected offset into arbitrary matching ELF bytes.
    data = read(data_address, data_size)
    assert len(data) >= 0x35 and data[:4] == b'\xf5\xf5\xdc\xdc'
    snapshot_size = struct.unpack_from('<Q', data, 4)[0] + 4
    assert 0x35 <= snapshot_size <= len(data)
    position = data.index(0, 0x34, min(snapshot_size, 4096)) + 1
    assert b'compressed-pointers' in data[0x34:position - 1].split(), 'This independent table locator requires compressed pointers'

    def unsigned_header_value():
        nonlocal position
        value = 0
        for shift in range(0, 70, 7):
            assert position < snapshot_size, 'Truncated clustered snapshot header'
            byte = data[position]
            position += 1
            value |= (byte & 0x7f) << shift
            if byte >= 0x80:
                return value
        raise AssertionError('Oversized clustered snapshot header integer')

    header = [unsigned_header_value() for _ in range(5)]
    expected_table_address = data_address + ((snapshot_size + 63) & ~63) + header[4] + 16
    assert table_address == expected_table_address, 'Table address disagrees with original snapshot header'
    canonical_maps, count, first_with_code, padding = struct.unpack('<IIII', read(table_address, 16))
    assert padding == 0 and 0 <= first_with_code <= count <= image_size // 4
    assert count - first_with_code == header[3], 'Retained Code count disagrees with original header'
    assert (count, first_with_code) == (manifest['table_length'], manifest['first_entry_with_code'])
    records = list(struct.iter_unpack('<II', read(table_address + 16, count * 8)))
    starts = [image_start + pc for pc, _ in records]
    # The matched VM checks its SDK-derived section header size. Here the
    # original PC table supplies the boundary, independently of the exporter.
    assert starts and starts[0] >= image_start + section_offset + 40
    assert all(a < b and a % 4 == 0 for a, b in zip(starts, starts[1:]))
    assert starts[-1] < image_end and starts[-1] % 4 == 0
    # Stack-map offsets follow the complete search table. They are bounded by
    # the canonical-map block in the table, independently of deserialization.
    assert canonical_maps >= 16 + count * 8
    assert all(16 + count * 8 <= smap < canonical_maps for _, smap in records)
    expected = list(zip(starts, starts[1:] + [image_end]))
    assert len(manifest['ranges']) == count == manifest['payload_count']
    for i, (row, span) in enumerate(zip(manifest['ranges'], expected)):
        assert (row['index'], row['table']) == (i, 0)
        assert (row['start'], row['end']) == span
        assert row['discarded_code'] == (i < first_with_code)

    # Pool comments can contain existing literal regex escapes such as \?.
    with warnings.catch_warnings():
        warnings.simplefilter('ignore', SyntaxWarning)
        tree = ast.parse((args.output / 'ida_script/addNames.py').read_text())
    exported, names = [], []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        if node.func.attr == 'add_func' and len(node.args) == 2:
            if all(isinstance(x, ast.Constant) and type(x.value) is int for x in node.args):
                exported.append(tuple(x.value for x in node.args))
        elif node.func.attr == 'set_name' and len(node.args) == 2:
            if all(isinstance(x, ast.Constant) for x in node.args):
                names.append(tuple(x.value for x in node.args))
    isolate_exported = [span for span in exported if image_start <= span[0] < span[1] <= image_end]
    assert isolate_exported == expected, 'IDA application ranges do not exactly match the ELF table'
    vm_exported = [span for span in exported if not image_start <= span[0] < span[1] <= image_end]
    if vm_exported:
        assert vm_image and (vm_image[0] + vm_image[1] <= image_start or image_end <= vm_image[0]), 'Unexpected ranges outside the application image'
        vm_start, vm_size = vm_image
        assert struct.unpack('<Q', read(vm_start, 8))[0] == vm_size
        assert all(vm_start <= start < end <= vm_start + vm_size for start, end in vm_exported)
        assert len(set(vm_exported)) == len(vm_exported), 'Duplicate VM-stub ranges'
    anonymous = {address for address, name in names if name.startswith('unattributed_code_')}
    known_names = sorted(address for address, name in names if not name.startswith('unattributed_code_'))
    for row in manifest['ranges']:
        pos = bisect.bisect_left(known_names, row['start'])
        named = pos < len(known_names) and known_names[pos] < row['end']
        assert named == row['has_metadata_name']
        assert (row['start'] in anonymous) == (not named)
    assert len(anonymous) == manifest['additional_exports']

    pattern = re.compile(r'^\s*//\s*(0x[0-9a-f]+): ([a-z][a-z0-9.]*)\s*(.*?)\s*$')
    def assembly_lines():
        for line in (args.output / 'asm/snapshot_code.asm').open():
            match = pattern.match(line)
            if match:
                yield int(match[1], 16), match[2], match[3].partition(';')[0].strip()

    lines = iter(assembly_lines())
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    instruction_count = 0
    for start, end in expected:
        cursor = start
        for address in range(start, end, 4):
            word = read(address, 4)
            instruction = next(md.disasm_lite(word, address), None)
            actual = next(lines, None)
            assert actual is not None and actual[0] == address, f'Missing assembly at {address:#x}'
            if instruction is not None:
                _, size, mnemonic, operands = instruction
                assert size == 4 and actual == (address, mnemonic, operands), f'Assembly mismatch at {address:#x}'
            else:
                mnemonic = unprivileged_load_mnemonic(word)
                assert mnemonic and actual[1] == mnemonic, f'Undecoded ELF word at {address:#x}'
            instruction_count += 1
            cursor += 4
        assert cursor == end, f'Undecoded ELF bytes at {cursor:#x}'
    assert next(lines, None) is None, 'Extra/duplicate assembly rows'
    assert instruction_count * 4 == image_end - starts[0]
    assert manifest['undecoded_words'] == 0

    retained_checks = None
    heap_entries_checked = None
    if args.vm_audit:
        audit = json.loads(args.vm_audit.read_text())
        assert len(audit['tables']) == 1
        table = audit['tables'][0]
        assert table['data_address'] == table_address
        assert table['retained_code_count'] == count - first_with_code
        assert len(table['entries']) == count
        for index, entry in enumerate(table['entries']):
            assert (entry['entry'], entry['pc_offset'], entry['stack_map_offset']) == (
                starts[index], records[index][0], records[index][1])
            if index >= first_with_code:
                assert entry['payload'] == starts[index]
                assert starts[index] <= entry['code_entry'] < expected[index][1]
                assert entry['size'] == expected[index][1] - starts[index]
        retained_checks = count - first_with_code
        known_entries = {row['entry'] for row in audit['known_functions'] + audit['known_stubs']}
        expected_vm_stubs = []
        if vm_image:
            vm_start, vm_size = vm_image
            expected_vm_stubs = [(row['entry'], row['entry'] + row['size']) for row in audit['known_stubs']
                                 if vm_start <= row['entry'] < row['entry'] + row['size'] <= vm_start + vm_size]
        assert sorted(vm_exported) == sorted(expected_vm_stubs), 'A retained VM-stub range was lost or changed'
        heap_entries = {row['entry'] for row in audit['heap_functions']
                        if row['has_code'] and starts[0] <= row['entry'] < image_end}
        assert heap_entries <= known_entries, 'A retained heap Function entry was not registered'
        heap_entries_checked = len(heap_entries)

    print(json.dumps({
        'status': 'PASSED', 'sample_sha256': hashlib.sha256(raw).hexdigest(),
        'raw_elf_table_address': hex(table_address), 'payload_count': count,
        'discarded_code_count': first_with_code, 'retained_code_count': count - first_with_code,
        'anonymous_exports': len(anonymous), 'metadata_named_payloads': count - len(anonymous),
        'ida_range_count': len(exported), 'ida_application_ranges_match_raw_table_exactly': True,
        'isolate_range_count': len(isolate_exported), 'separate_vm_stub_ranges': len(vm_exported),
        'raw_assembly_instructions_checked': instruction_count,
        'payload_bytes_checked': instruction_count * 4, 'payload_coverage': 1.0,
        'image_header_bytes': section_offset,
        'section_metadata_and_alignment_bytes': starts[0] - image_start - section_offset,
        'noncode_prefix_bytes': starts[0] - image_start, 'image_bytes': image_size,
        'retained_vm_objects_cross_checked': retained_checks,
        'retained_heap_function_entries_checked': heap_entries_checked,
        'limits': 'Native payload coverage only. Anonymous names, Dart types and high-level semantics are not recovered by this check.',
    }, indent=2))


if __name__ == '__main__':
    main()
