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


def main():
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
        symbol = symbols.get_symbol_by_name('_kDartSnapshotText')[0]
        image_start, symbol_size = symbol['st_value'], symbol['st_size']

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
    canonical_maps, count, first_with_code, padding = struct.unpack('<IIII', read(table_address, 16))
    assert padding == 0 and 0 <= first_with_code <= count <= image_size // 4
    assert (count, first_with_code) == (manifest['table_length'], manifest['first_entry_with_code'])
    records = list(struct.iter_unpack('<II', read(table_address + 16, count * 8)))
    starts = [image_start + pc for pc, _ in records]
    assert starts[0] == image_start + 128
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
    assert exported == expected, 'IDA ranges do not exactly match the ELF table'
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
        for address, size, mnemonic, operands in md.disasm_lite(read(start, end - start), start):
            assert address == cursor and size == 4
            assert next(lines) == (address, mnemonic, operands), f'Assembly mismatch at {address:#x}'
            instruction_count += 1
            cursor += size
        assert cursor == end, f'Undecoded ELF bytes at {cursor:#x}'
    assert next(lines, None) is None, 'Extra/duplicate assembly rows'
    assert instruction_count * 4 == image_end - starts[0]
    assert manifest['undecoded_words'] == 0

    retained_checks = None
    if args.vm_audit:
        audit = json.loads(args.vm_audit.read_text())
        assert len(audit['tables']) == 1
        table = audit['tables'][0]
        assert table['data_address'] == table_address
        assert table['retained_code_count'] == count - first_with_code
        for index, entry in enumerate(table['entries']):
            assert (entry['entry'], entry['pc_offset'], entry['stack_map_offset']) == (
                starts[index], records[index][0], records[index][1])
            if index >= first_with_code:
                assert entry['payload'] == starts[index]
                assert starts[index] <= entry['code_entry'] < expected[index][1]
                assert entry['size'] == expected[index][1] - starts[index]
        retained_checks = count - first_with_code

    print(json.dumps({
        'status': 'PASSED', 'sample_sha256': hashlib.sha256(raw).hexdigest(),
        'raw_elf_table_address': hex(table_address), 'payload_count': count,
        'discarded_code_count': first_with_code, 'retained_code_count': count - first_with_code,
        'anonymous_exports': len(anonymous), 'metadata_named_payloads': count - len(anonymous),
        'ida_range_count': len(exported), 'ida_ranges_match_raw_table_exactly': True,
        'raw_assembly_instructions_checked': instruction_count,
        'payload_bytes_checked': instruction_count * 4, 'payload_coverage': 1.0,
        'image_header_bytes': section_offset,
        'section_metadata_and_alignment_bytes': starts[0] - image_start - section_offset,
        'noncode_prefix_bytes': starts[0] - image_start, 'image_bytes': image_size,
        'retained_vm_objects_cross_checked': retained_checks,
        'limits': 'Native payload coverage only. Anonymous names, Dart types and high-level semantics are not recovered by this check.',
    }, indent=2))


if __name__ == '__main__':
    main()
