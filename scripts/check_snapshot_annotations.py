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
from functools import lru_cache
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


def constant_move(word):
    """Decode move producers from original words, independently of Capstone aliases."""
    bits = 64 if word >> 31 else 32
    mask = (1 << bits) - 1
    if word & 0x1f800000 == 0x12800000:
        op, shift, immediate = (word >> 29) & 3, ((word >> 21) & 3) * 16, (word >> 5) & 0xffff
        if shift >= bits or op == 1:
            return None
        value = immediate << shift
        return ('keep' if op == 3 else 'literal', word & 31, bits,
                (value, 0xffff << shift) if op == 3 else (~value if op == 0 else value) & mask)
    if word & 0x7fe0ffe0 == 0x2a0003e0:  # ORR Rd, ZR, Rm (MOV register)
        return 'copy', word & 31, bits, (word >> 16) & 31
    if word & 0x7f8003e0 == 0x320003e0:  # ORR Rd, ZR, bitmask (MOV immediate)
        n, r, s = (word >> 22) & 1, (word >> 16) & 63, (word >> 10) & 63
        length = ((n << 6) | (~s & 63)).bit_length() - 1
        if length < 1 or (bits == 32 and n):
            return None
        size, levels = 1 << length, (1 << length) - 1
        r, s = r & levels, s & levels
        if s == levels:
            return None
        element = (1 << (s + 1)) - 1
        element = ((element >> r) | (element << (size - r))) & ((1 << size) - 1)
        return 'literal', word & 31, bits, sum(element << shift for shift in range(0, bits, size))
    return None


def integer_operation(word):
    """Unshifted ADD/SUB and extracting UBFM encodings, from original words."""
    bits, destination = (64 if word >> 31 else 32), word & 31
    if word & 0x1f000000 == 0x11000000 and not word & (1 << 29):
        left = (word >> 5) & 31
        if left == 31 or destination == 31:  # SP is not a known zero register
            return None
        return ('sub' if word & (1 << 30) else 'add', destination, bits,
                (left, 'immediate', ((word >> 10) & 0xfff) << (12 if word & (1 << 22) else 0)))
    if word & 0x1f200000 == 0x0b000000 and not word & (1 << 29):
        if (word >> 22) & 3 or (word >> 10) & 63:
            return None
        return ('sub' if word & (1 << 30) else 'add', destination, bits,
                ((word >> 5) & 31, 'register', (word >> 16) & 31))
    if word & 0x7f800000 == 0x53000000 and ((word >> 22) & 1) == (bits == 64):
        lsb, last = (word >> 16) & 63, (word >> 10) & 63
        if lsb <= last < bits:
            return 'extract', destination, bits, ((word >> 5) & 31, lsb, last - lsb + 1)
    return None


def decode_dispatch_table(raw, code_entries, null_target, max_entries=1 << 24):
    """Bounded root-unit Dart dispatch stream reader; no runtime/reader pointers."""
    cursor = 0

    def integer(marker):
        nonlocal cursor
        value = 0
        for shift in range(0, 70, 7):
            assert cursor < len(raw), 'Truncated dispatch integer'
            byte = raw[cursor]
            cursor += 1
            if byte >= 128:
                value |= (byte - marker) << shift
                assert -(1 << 63) <= value < (1 << 64), 'Dispatch integer overflow'
                return value
            value |= byte << shift
        raise AssertionError('Overlong dispatch integer')

    length = integer(128)
    assert 0 <= length <= max_entries, 'Dispatch table length limit'
    if length == 0:
        assert cursor == len(raw)
        return []
    assert integer(128) >= 0  # first Code cluster reference, unused for root indices
    entries, recent, next_recent, previous = [], [None] * 64, 0, None
    while len(entries) < length:
        encoded = integer(192)
        if encoded == 0:
            previous = null_target
        elif encoded < 0:
            assert 0 <= ~encoded < 64 and recent[~encoded] is not None, 'Invalid recent dispatch entry'
            previous = recent[~encoded]
        elif encoded < 64:
            assert previous is not None and len(entries) + encoded <= length, 'Invalid dispatch repeat'
            entries.extend([previous] * encoded)
            continue
        else:
            index = encoded - 65  # serialized code index is one-based
            assert 0 <= index < len(code_entries), 'Invalid dispatch Code index'
            previous = code_entries[index]
            recent[next_recent] = previous
            next_recent = (next_recent + 1) % 64
        entries.append(previous)
    assert cursor == len(raw), 'Trailing dispatch data'
    return entries


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('libapp', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--log', type=Path, required=True,
                        help='Reader log with load address, used to check relocation normalization')
    parser.add_argument('--vm-audit', type=Path, help='Separate VM numerical audit for retained Code dispatch entries')
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
    audit_data = json.loads(args.vm_audit.read_text()) if args.vm_audit else None
    load_base = int(re.search(r'^libapp is loaded at (0x[0-9a-f]+)$', args.log.read_text(), re.M)[1], 16)
    manifest = json.loads((args.output / 'snapshot_code.json').read_text())
    nodes, profile = graph['nodes'], graph['profile']
    pool_catalog = {row['index']: row for row in graph['pool_catalog']}
    count = manifest['table_length']
    records = struct.iter_unpack('<II', read(manifest['table_data_address'] + 16, 8 * count))
    starts = [manifest['image_start'] + pc for pc, _ in records]
    ends = starts[1:] + [manifest['image_end']]
    assert [(n['start'], n['end']) for n in nodes] == list(zip(starts, ends))
    assert all(n['decoded'] for n in nodes), 'Partially decoded payload; cannot claim complete graph'
    dispatch = graph.get('dispatch_table', {'entries': [], 'origin': 0})
    if dispatch['entries']:
        assert args.vm_audit, 'Dispatch validation requires --vm-audit (BLUTTER_COVERAGE_AUDIT)'
        audit = audit_data['tables']
        assert len(audit) == 1 and audit[0]['count'] == count
        code_entries = []
        for i, entry in enumerate(audit[0]['entries']):
            assert entry['index'] == i and entry['entry'] == starts[i]
            code_entries.append(entry.get('code_entry', starts[i]))
        decoded = decode_dispatch_table(read(dispatch['snapshot_address'], dispatch['snapshot_size']), code_entries, dispatch['null_target'])
        assert decoded == dispatch['entries'], 'Dispatch entries differ from original compressed stream'
        assert dispatch['origin'] == 4096, 'Unexpected matched ARM64 dispatch bias'
        for target in decoded:
            assert target is None or (target % 4 == 0 and len(read(target, 4)) == 4)

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
            if profile.get('dispatch_register'):
                roots[profile['dispatch_register']] = 'dispatch_table'
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

        @lru_cache(maxsize=None)
        def constant_before(index, register, budget=64):
            if not budget:
                return None
            cursor = index
            while cursor:
                if instructions[cursor].address in entries:
                    return None
                cursor -= 1
                ins = instructions[cursor]
                if any(ins.group(g) for g in (cs.CS_GRP_JUMP, cs.CS_GRP_CALL, cs.CS_GRP_RET)):
                    return None
                if register not in writes[cursor]:
                    continue
                word = int.from_bytes(ins.bytes, 'little')
                producer = constant_move(word) or integer_operation(word)
                if producer is None:
                    return None
                kind, destination, bits, value = producer
                assert register == f'x{destination}'
                proof = []
                if kind in ('add', 'sub', 'extract'):
                    source = value[0]
                    left = (0, []) if source == 31 else constant_before(cursor, f'x{source}', budget - 1)
                    if left is None:
                        return None
                    old, proof = left
                    if kind == 'extract':
                        value = (old >> value[1]) & ((1 << value[2]) - 1)
                    else:
                        right = (value[2], []) if value[1] == 'immediate' else (0, []) if value[2] == 31 else constant_before(cursor, f'x{value[2]}', budget - 1)
                        if right is None:
                            return None
                        proof = sorted(set(proof + right[1]))
                        value = old + right[0] if kind == 'add' else old - right[0]
                elif kind != 'literal':
                    source = destination if kind == 'keep' else value
                    previous = (0, []) if source == 31 else constant_before(cursor, f'x{source}', budget - 1)
                    if previous is None:
                        return None
                    old, proof = previous
                    value = ((old & ~value[1]) | value[0]) if kind == 'keep' else old
                if len(proof) >= 64:
                    return None
                return value & ((1 << bits) - 1), proof + [ins.address]
            return None

        @lru_cache(maxsize=None)
        def index_before(index, register, budget=64):
            if not budget:
                return None
            cursor = index
            while cursor:
                if instructions[cursor].address in entries:
                    return None
                cursor -= 1
                ins = instructions[cursor]
                if any(ins.group(g) for g in (cs.CS_GRP_JUMP, cs.CS_GRP_CALL, cs.CS_GRP_RET)):
                    return None
                if register not in writes[cursor]:
                    continue
                word = int.from_bytes(ins.bytes, 'little')
                op = constant_move(word) or integer_operation(word)
                if not op or op[2] != 64:
                    return None
                kind, destination, _, value = op
                if kind == 'extract' and value[2] <= 32:
                    return (ins.address, f'x{value[0]}', value[1], value[2], 0, [ins.address])
                if kind == 'copy':
                    previous = index_before(cursor, f'x{value}', budget - 1)
                    right, sign = (0, []), 1
                elif kind in ('add', 'sub'):
                    previous = index_before(cursor, f'x{value[0]}', budget - 1)
                    right = (value[2], []) if value[1] == 'immediate' else (0, []) if value[2] == 31 else constant_before(cursor, f'x{value[2]}')
                    sign = 1 if kind == 'add' else -1
                else:
                    return None
                if previous is None or right is None:
                    return None
                site, source, lsb, size, addend, proof = previous
                addend += sign * signed(right[0], 64)
                if not -(1 << 63) <= addend <= (1 << 63) - (1 << size):
                    return None
                proof = sorted(set(proof + right[1]))
                return (site, source, lsb, size, addend, proof + [ins.address]) if len(proof) < 64 else None
            return None

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
            constants = edge.get('register_constants', [])
            assert len({c['register'] for c in constants}) == len(constants)
            assert not constants or edge['kind'] in ('call', 'indirect_call')
            for fact in constants:
                expected = constant_before((edge['site'] - start) // 4, fact['register'])
                assert expected == (int(fact['bits'], 16), fact['proof']), (hex(edge['site']), fact, expected)
                proof_checks += 1
            if not edge['via_kind']:
                assert edge['via_offset'] is None and not edge['proof']
                assert edge.get('snapshot_target') is None and edge.get('via_field_offset') is None and not edge.get('index_register')
                continue
            cursor = (edge['site'] - start) // 4
            register, moved = edge['target_register'], []
            field = None
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
                if edge['via_kind'] == 'dispatch_table':
                    assert ins.id == a.ARM64_INS_LDR and len(ins.operands) == 2 and not ins.writeback
                    op = ins.operands[1]
                    assert op.type == a.ARM64_OP_MEM and width(ins.operands[0].reg) == width(op.mem.index) == 8
                    assert op.ext == 0 and op.shift.type == a.ARM64_SFT_LSL and op.shift.value == 3
                    kind, offset, proof = address_origin(cursor, reg(op.mem.base), op.mem.disp)
                    assert (edge['via_kind'], edge['via_offset'], edge['index_register'], edge['proof']) == (kind, offset, reg(op.mem.index), proof + [ins.address] + list(reversed(moved)))
                    access = edge['dispatch']
                    assert edge['via_field_offset'] is None
                    constant = constant_before(cursor, reg(op.mem.index))
                    if access['index'] is not None:
                        assert constant and (signed(constant[0], 64), constant[1]) == (access['index'], access['proof'])
                        assert access['expression'] is None
                        table_index = dispatch['origin'] + offset // 8 + access['index'] if offset % 8 == 0 else None
                        if table_index is not None and not -(1 << 63) <= table_index < (1 << 63):
                            table_index = None
                        assert access['table_index'] == table_index
                        expected_target = None
                        resolution = 'misaligned_base' if offset % 8 else 'table_unavailable' if not dispatch['entries'] else 'out_of_bounds'
                        if offset % 8 == 0 and table_index is not None and 0 <= table_index < len(dispatch['entries']):
                            expected_target = dispatch['entries'][table_index]
                            resolution = 'unmapped_entry' if expected_target is None else 'null_error_entry' if expected_target == dispatch['null_target'] else 'snapshot_entry'
                        assert (edge['snapshot_target'], access['resolution']) == (expected_target, resolution)
                    else:
                        assert constant is None and access['table_index'] is None and not access['proof'] and edge['snapshot_target'] is None
                        assert access['resolution'] == 'unknown_index'
                        expression = access['expression']
                        if expression:
                            assert index_before(cursor, reg(op.mem.index)) == (expression['site'], expression['source_register'], expression['lsb'], expression['width'], expression['addend'], expression['proof'])
                    break
                parts = 2 if ins.id == a.ARM64_INS_LDP else 1
                part = next(n for n in range(parts) if reg(ins.operands[n].reg) == register)
                base, displacement, size = memory(ins, part)
                assert size == 8
                if edge['via_kind'] == 'pool_code_entry' and field is None:
                    assert parts == 1
                    field = displacement
                    moved.append(ins.address)
                    register = base
                    continue
                kind, offset, proof = address_origin(cursor, base, displacement)
                if field is not None:
                    assert kind == 'pool' and edge['via_field_offset'] == field
                    relative = offset - profile['pool_data_offset']
                    assert relative >= 0 and relative % profile['pool_slot_size'] == 0
                    slot = pool_catalog[relative // profile['pool_slot_size']]
                    assert {e['field_offset']: e['target'] for e in slot['entry_points']}[field] == edge['snapshot_target']
                    kind = 'pool_code_entry'
                else:
                    assert edge.get('snapshot_target') is None and edge.get('via_field_offset') is None
                assert not edge.get('index_register')
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
        if slot.get('entry_points'):
            assert slot['kind'] == 'tagged_object' and slot['description'].startswith(('Code:', 'Stub:'))
            normal = int(re.search(r'\((0x[0-9a-f]+)\)$', slot['description'])[1], 16)
            # The renderer independently exports the normal Code entry. Other
            # SDK-selected entry fields have only instruction/export checks here.
            assert normal in {entry['target'] for entry in slot['entry_points']}
            for entry in slot['entry_points']:
                assert entry['target'] % 4 == 0 and len(read(entry['target'], 4)) == 4
    from check_receiver_analysis import check_receivers
    receiver_checks = check_receivers(graph, read, lambda raw, start: decode_payload(md, raw, start), audit_data)
    print(json.dumps({'status': 'PASSED', 'sample_sha256': hashlib.sha256(raw).hexdigest(),
                      'payloads': len(nodes), 'edges_checked_from_machine_words': len(graph['edges']),
                      'edge_kinds': dict(Counter(e['kind'] for e in graph['edges'])),
                      'references_checked_backwards': len(graph['references']),
                      'reference_kinds': dict(Counter(r['kind'] for r in graph['references'])),
                      'reference_and_indirect_provenance_checks': proof_checks,
                      'snapshot_code_entry_edges': sum(e['via_kind'] == 'pool_code_entry' and e.get('snapshot_target') is not None for e in graph['edges']),
                      'indexed_dispatch_edges': sum(e['via_kind'] == 'dispatch_table' for e in graph['edges']),
                      'dispatch_table_entries_checked_from_stream': len(dispatch['entries']),
                      'dispatch_exact_snapshot_targets': sum(e['via_kind'] == 'dispatch_table' and e.get('snapshot_target') is not None for e in graph['edges']),
                      'dispatch_index_expressions': sum(bool(e.get('dispatch', {}).get('expression')) for e in graph['edges'] if e.get('dispatch')),
                      'constant_register_observations': sum(len(e.get('register_constants', [])) for e in graph['edges']),
                      'pool_values_cross_checked': len(used_slots),
                      'thread_fields_consistent_with_ida_export': len(thread_catalog),
                      **receiver_checks,
                      'limits': 'Checks instruction facts and export consistency. Constant producers are decoded from original machine words. Does not independently prove SDK field layouts, runtime indirect targets, argument liveness, source types or Dart semantics.'}, indent=2))


if __name__ == '__main__':
    main()
