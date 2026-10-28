#!/usr/bin/env python3
"""Check annotation facts against original ARM64 ELF bytes and separate exports.

Branch targets are decoded from machine words without Capstone. Reference
provenance is checked backwards from each use, including intervening clobbers
and known incoming branches. This does not prove source-level Dart semantics.
"""
import argparse
import bisect
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import re
import struct
from dataclasses import dataclass

import capstone as cs
from capstone import arm64 as a
from elftools.elf.elffile import ELFFile
from check_blutter_output import unprivileged_load_mnemonic


@dataclass
class RecoveredLoad:
    instruction: object
    id: int
    mnemonic: str
    bytes: bytes

    def __getattr__(self, name):
        return getattr(self.instruction, name)


def decode_payload(decoder, raw, start):
    instructions = list(decoder.disasm(raw, start))
    # Capstone 5 rejects allocated unprivileged loads when base == destination.
    # Validate their original encoding, then obtain only equivalent operands
    # and register effects from LDUR. Keep the original opcode and instruction ID.
    for offset in range(len(instructions) * 4, len(raw), 4):
        word = raw[offset:offset + 4]
        assert len(word) == 4
        address = start + offset
        insn = next(decoder.disasm(word, address), None)
        if insn is None:
            mnemonic = unprivileged_load_mnemonic(word)
            assert mnemonic, f'Unrecognized original instruction at {address:#x}'
            proxy = (int.from_bytes(word, 'little') & ~0xc00).to_bytes(4, 'little')
            insn = next(decoder.disasm(proxy, address), None)
            assert insn and insn.mnemonic == mnemonic.replace('ldtr', 'ldur', 1)
            insn = RecoveredLoad(insn, getattr(a, 'ARM64_INS_' + mnemonic.upper()), mnemonic, word)
        instructions.append(insn)
    return instructions


def folded_immediate_bits(description, load_base):
    target = re.match(r'^(0x[0-9a-f]{1,16}) - ', description)
    assert target, 'Expected the folded UnlinkedCall immediate representation'
    # The older pool renderer subtracts the mapping base from every adjacent
    # immediate, including VM code values and numeric bits. Undo it exactly;
    # this does not establish that the value is a callable target.
    return (int(target[1], 16) + load_base) & ((1 << 64) - 1)


def signed(value, bits):
    return value - (1 << bits) if value & (1 << (bits - 1)) else value


def branch(word, pc):
    if word & 0xfc000000 in (0x94000000, 0x14000000):
        return ('call' if word & 0x80000000 else 'jump', pc + signed(word & 0x3ffffff, 26) * 4)
    if word & 0xff000010 == 0x54000000 or word & 0x7e000000 == 0x34000000:
        return 'conditional_jump', pc + signed((word >> 5) & 0x7ffff, 19) * 4
    if word & 0x7e000000 == 0x36000000:
        return 'conditional_jump', pc + signed((word >> 5) & 0x3fff, 14) * 4
    if word & 0xfffffc1f in (0xd61f0000, 0xd63f0000):
        return ('indirect_call' if word & 0x200000 else 'indirect_jump', 'x' + str((word >> 5) & 31))
    return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('libapp', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--log', type=Path, required=True,
                        help='Reader log with load address, used to check relocation normalization')
    args = parser.parse_args()
    raw = args.libapp.read_bytes()
    with args.libapp.open('rb') as stream:
        elf = ELFFile(stream)
        segments = [(p['p_vaddr'], p['p_filesz'], p['p_offset']) for p in elf.iter_segments() if p['p_type'] == 'PT_LOAD']

    def read(address, length):
        for base, size, pos in segments:
            if base <= address and address + length <= base + size:
                return raw[pos + address - base:pos + address - base + length]
        raise AssertionError(f'Unmapped span {address:#x}')

    graph = json.loads((args.output / 'snapshot_calls.json').read_text())
    load_base = int(re.search(r'^libapp is loaded at (0x[0-9a-f]+)$', args.log.read_text(), re.M)[1], 16)
    manifest = json.loads((args.output / 'snapshot_code.json').read_text())
    nodes, profile = graph['nodes'], graph['profile']
    count = manifest['table_length']
    records = struct.iter_unpack('<II', read(manifest['table_data_address'] + 16, 8 * count))
    starts = [manifest['image_start'] + pc for pc, _ in records]
    ends = starts[1:] + [manifest['image_end']]
    assert [(n['start'], n['end']) for n in nodes] == list(zip(starts, ends))
    assert all(n['decoded'] for n in nodes), 'Partially decoded payload; cannot claim complete graph'

    def node_at(address):
        index = bisect.bisect_right(starts, address) - 1
        return nodes[index] if index >= 0 and address < ends[index] else None

    entries = set()
    for node in nodes:
        for name in node['names']:
            assert node['start'] <= name['address'] < node['end']
            entries.add(name['address'])
        assert node['label'] == (node['names'][0]['name'] if node['names'] else f"unattributed_code_{node['start']:x}")
    expected_edges = {}
    for start, end in zip(starts, ends):
        for index, (word,) in enumerate(struct.iter_unpack('<I', read(start, end - start))):
            pc = start + index * 4
            result = branch(word, pc)
            if not result:
                continue
            kind, target = result
            if isinstance(target, int):
                entries.add(target)
            if kind != 'call' and isinstance(target, int) and start <= target < end:
                continue
            expected_edges[pc] = (start, kind, target)
    assert len(graph['edges']) == len(expected_edges)
    edges_by_payload = defaultdict(list)
    for edge in graph['edges']:
        start, kind, target = expected_edges.pop(edge['site'])
        assert (edge['source'], edge['kind']) == (start, kind)
        if isinstance(target, int):
            assert edge['target'] == target
            node = node_at(target)
            assert edge['target_payload'] == (node['start'] if node else None)
            assert edge['target_label'] == (node['label'] if node else '')
        else:
            assert edge['target_register'] == target
            assert edge['target'] is edge['target_payload'] is None
        edges_by_payload[start].append(edge)
    assert not expected_edges

    references_by_payload = defaultdict(list)
    for ref in graph['references']:
        node = node_at(ref['site'])
        assert node and node['start'] == ref['payload']
        references_by_payload[ref['payload']].append(ref)
    thread_catalog = {row['offset']: row['name'] for row in graph['thread_catalog']}
    # Separate IDA export must agree on target Thread offsets (consistency,
    # not independent proof of the ABI names themselves).
    header = (args.output / 'ida_script/ida_dart_struct.h').read_text().split('} DartThread;')[0]
    fields = re.findall(r'__int64 (\w+);', header)
    for offset, name in thread_catalog.items():
        assert offset % 8 == 0 and fields[offset // 8] == name

    md = cs.Cs(cs.CS_ARCH_ARM64, cs.CS_MODE_ARM)
    md.detail = True
    proof_checks = 0
    for node in nodes:
        start, end = node['start'], node['end']
        instructions = decode_payload(md, read(start, end - start), start)
        assert len(instructions) * 4 == end - start
        def reg(number):
            name = md.reg_name(number)
            return {'fp': 'x29', 'lr': 'x30'}.get(name, name.replace('w', 'x', 1) if name.startswith('w') and name[1:].isdigit() else name)
        def width(number):
            name = md.reg_name(number)
            return 8 if name.startswith(('x', 'd')) or name in ('fp', 'lr', 'sp') else 4 if name.startswith(('w', 's')) else 16 if name.startswith('q') else 0
        writes = [{reg(r) for r in ins.regs_access()[1]} for ins in instructions]
        roots_written = set().union(*writes)

        def memory(ins, part=0):
            pair = ins.id in (a.ARM64_INS_LDP, a.ARM64_INS_STP)
            op = ins.operands[2 if pair else 1]
            assert op.type == a.ARM64_OP_MEM and not op.mem.index and not ins.writeback
            size = width(ins.operands[part].reg)
            return reg(op.mem.base), op.mem.disp + part * size, size

        def address_origin(index, register, displacement):
            proof = []
            roots = {profile['pool_register']: 'pool', profile['thread_register']: 'thread'}
            cursor = index
            while register not in roots:
                assert instructions[cursor].address not in entries, 'Alias crosses known entry'
                cursor -= 1
                assert cursor >= 0, 'Alias has no definition'
                ins = instructions[cursor]
                assert not any(ins.group(g) for g in (cs.CS_GRP_JUMP, cs.CS_GRP_CALL, cs.CS_GRP_RET)), 'Alias crosses transfer'
                if register not in writes[cursor]:
                    continue
                ops = ins.operands
                assert width(ops[0].reg) == 8 and reg(ops[0].reg) == register
                assert ops[1].type == a.ARM64_OP_REG and width(ops[1].reg) == 8
                if ins.id in (a.ARM64_INS_ADD, a.ARM64_INS_SUB):
                    assert len(ops) == 3 and ops[2].type == a.ARM64_OP_IMM
                    assert ops[2].shift.type in (0, a.ARM64_SFT_LSL)
                    delta = ops[2].imm << ops[2].shift.value
                    displacement += delta if ins.id == a.ARM64_INS_ADD else -delta
                else:
                    assert ins.id == a.ARM64_INS_MOV and len(ops) == 2
                proof.append(ins.address)
                register = reg(ops[1].reg)
            assert register not in roots_written, 'Assumed ABI root is overwritten'
            return roots[register], displacement, list(reversed(proof))

        for ref in references_by_payload[start]:
            index = (ref['site'] - start) // 4
            ins = instructions[index]
            assert ins.id in (a.ARM64_INS_LDR, a.ARM64_INS_LDUR, a.ARM64_INS_LDP,
                              a.ARM64_INS_STR, a.ARM64_INS_STUR, a.ARM64_INS_STP)
            assert ref['access'] == ('load' if ins.mnemonic.startswith('ld') else 'store')
            choices = []
            for part in range(2 if ins.id in (a.ARM64_INS_LDP, a.ARM64_INS_STP) else 1):
                base, displacement, size = memory(ins, part)
                kind, offset, proof = address_origin(index, base, displacement)
                choices.append((base, size, kind, offset, proof))
            assert (ref['base_register'], ref['width'], ref['kind'], ref['offset'], ref['proof']) in choices
            if ref['kind'] == 'pool':
                relative = ref['offset'] - profile['pool_data_offset']
                slot = relative // profile['pool_slot_size']
                valid = relative >= 0 and relative % profile['pool_slot_size'] == 0 and slot < profile['pool_length'] and ref['width'] == profile['pool_slot_size']
                assert ref['pool_index'] == (slot if valid else None)
            else:
                assert ref['field_name'] == thread_catalog.get(ref['offset'], '') and ref['pool_index'] is None
            proof_checks += 1

        for edge in edges_by_payload[start]:
            if not edge['via_kind']:
                assert edge['via_offset'] is None and not edge['proof']
                continue
            cursor = (edge['site'] - start) // 4
            register, moved = edge['target_register'], []
            while True:
                assert instructions[cursor].address not in entries
                cursor -= 1
                assert cursor >= 0
                ins = instructions[cursor]
                assert not any(ins.group(g) for g in (cs.CS_GRP_JUMP, cs.CS_GRP_CALL, cs.CS_GRP_RET))
                if register not in writes[cursor]:
                    continue
                if ins.id == a.ARM64_INS_MOV:
                    assert width(ins.operands[0].reg) == width(ins.operands[1].reg) == 8
                    moved.append(ins.address)
                    register = reg(ins.operands[1].reg)
                    continue
                assert ins.id in (a.ARM64_INS_LDR, a.ARM64_INS_LDUR, a.ARM64_INS_LDP)
                parts = 2 if ins.id == a.ARM64_INS_LDP else 1
                part = next(n for n in range(parts) if reg(ins.operands[n].reg) == register)
                base, displacement, size = memory(ins, part)
                assert size == 8
                kind, offset, proof = address_origin(cursor, base, displacement)
                assert (edge['via_kind'], edge['via_offset'], edge['proof']) == (kind, offset, proof + [ins.address] + list(reversed(moved)))
                break
            proof_checks += 1

    pp = (args.output / 'pp.txt').read_text()
    matches = list(re.finditer(r'^\[pp\+(0x[0-9a-f]+)\] ', pp, re.M))
    values = {int(match[1], 16): pp[match.end():matches[i+1].start() if i+1 < len(matches) else len(pp)].rstrip('\n') for i, match in enumerate(matches)}
    used_slots = {r['pool_index'] for r in graph['references'] if r['pool_index'] is not None}
    assert {s['index'] for s in graph['pool_catalog']} == used_slots
    for slot in graph['pool_catalog']:
        offset = profile['pool_data_offset'] + slot['index'] * profile['pool_slot_size']
        value = values.get(offset)
        if value is None:
            # The upstream pp.txt exporter folds the adjacent target/cache
            # slot into the preceding UnlinkedCall row.
            previous = values[offset - profile['pool_slot_size']]
            assert previous.startswith('UnlinkedCall: ')
            value = previous.removeprefix('UnlinkedCall: ')
            if slot['kind'] == 'text_address_value':
                assert int(slot['description'].rsplit(' ', 1)[1], 16) == int(re.match(r'0x[0-9a-f]+', value)[0], 16)
                continue
            if slot['kind'] == 'immediate':
                assert folded_immediate_bits(value, load_base) == int(slot['description'].split('bits: ')[1], 16)
                continue
        elif slot['kind'] == 'text_address_value':
            assert value.startswith('IMM:')
            address = int(slot['description'].rsplit(' ', 1)[1], 16)
            assert manifest['image_start'] <= address < manifest['image_end']
            assert int(re.findall(r'0x[0-9a-f]+', value)[-1], 16) == address + load_base
            continue
        if slot['kind'] == 'tagged_object':
            assert slot['description'] == value, (slot['index'], slot['description'], value)
        elif slot['kind'] == 'immediate':
            assert value.startswith('IMM:')
            assert int(slot['description'].split('bits: ')[1], 16) == int(re.findall(r'0x[0-9a-f]+', value)[-1], 16)
        elif slot['kind'] == 'unlinked_call':
            assert value.startswith('UnlinkedCall:') and slot['description'] == 'UnlinkedCall: target unresolved'
        else:
            assert slot['kind'] == 'native_function' and value.startswith('NativeFn:')
            assert slot['description'] == 'runtime native binding; target unresolved'
    print(json.dumps({'status': 'PASSED', 'sample_sha256': hashlib.sha256(raw).hexdigest(),
                      'payloads': len(nodes), 'edges_checked_from_machine_words': len(graph['edges']),
                      'edge_kinds': dict(Counter(e['kind'] for e in graph['edges'])),
                      'references_checked_backwards': len(graph['references']),
                      'reference_kinds': dict(Counter(r['kind'] for r in graph['references'])),
                      'reference_and_indirect_provenance_checks': proof_checks,
                      'pool_values_cross_checked': len(used_slots),
                      'thread_fields_consistent_with_ida_export': len(thread_catalog),
                      'limits': 'Checks instruction facts and export consistency. Does not independently prove all Thread ABI names, indirect targets, source types or Dart semantics.'}, indent=2))


if __name__ == '__main__':
    main()
