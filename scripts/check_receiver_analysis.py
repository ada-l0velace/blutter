"""Check inductive receiver CFG certificates against original instructions.

This checks every incoming edge against declared block invariants, rather than
rerunning the producer's fixed-point solver. SDK object classes are trusted
inputs cross-checked through the separate numerical VM audit.
"""
from collections import deque

import capstone as cs
from capstone import arm64 as a

from check_snapshot_annotations import branch, constant_move, integer_operation


UNKNOWN, WORD, RANGE, OBJECT, HEADER, POOL, DISPATCH, TARGET, STACK = range(9)
EMPTY = (UNKNOWN, 0, 0, 0)
MASK64 = (1 << 64) - 1


def signed(value):
    return value - (1 << 64) if value >> 63 else value


def fact(kind, value=0, aux=0, origin=0):
    return kind, value & MASK64, aux & MASK64, origin


def reg(ins, number):
    name = ins.reg_name(number)
    if name in ('fp', 'lr'):
        return 29 if name == 'fp' else 30
    return int(name[1:]) if name.startswith(('x', 'w')) and name[1:].isdigit() else -1


def width(ins, number):
    name = ins.reg_name(number)
    return 32 if name.startswith('w') else 64 if name.startswith('x') or name in ('fp', 'lr') else 0


def read_reg(state, ins, number):
    if number in (a.ARM64_REG_XZR, a.ARM64_REG_WZR):
        return fact(WORD)
    index = reg(ins, number)
    if index < 0:
        return EMPTY
    value = state[index]
    if width(ins, number) == 32:
        if value[0] in (WORD, RANGE):
            return fact(value[0], value[1] & 0xffffffff if value[0] == WORD else min(value[1], 0xffffffff))
        if value[0] != HEADER:
            return fact(RANGE, 0xffffffff)
    return value


def supported_operand(state, ins, operand, bits):
    if operand.ext:
        return EMPTY
    if operand.type == a.ARM64_OP_IMM and operand.imm >= 0 and (not operand.shift.type or (operand.shift.type == a.ARM64_SFT_LSL and operand.shift.value == 12)):
        return fact(WORD, operand.imm << (12 if operand.shift.type else 0))
    if operand.type == a.ARM64_OP_REG and width(ins, operand.reg) == bits and (not operand.shift.type or (operand.shift.type == a.ARM64_SFT_LSL and operand.shift.value == 0)):
        return read_reg(state, ins, operand.reg)
    return EMPTY


def entails(producer, declared):
    if declared[0] == UNKNOWN:
        return True
    if declared[0] == RANGE and producer[0] in (RANGE, WORD):
        return producer[1] <= declared[1]
    return producer == declared


def check_receivers(graph, read, decode, audit):
    claims = {e['site']: e['static_dispatch'] for e in graph['edges'] if e.get('static_dispatch') is not None}
    certificates = graph.get('receiver_certificates', [])
    assert len(claims) == sum(e.get('static_dispatch') is not None for e in graph['edges'])
    assert len({c['payload'] for c in certificates}) == len(certificates)
    if not claims:
        assert not certificates
        return {'receiver_claims_checked': 0, 'receiver_incoming_edges_checked': 0}
    assert audit, 'Receiver checking requires the separate VM audit'
    metadata, profile = graph['receiver_metadata'], graph['profile']
    assert 0 < metadata['class_id_bits'] <= 32 and metadata['class_id_shift'] + metadata['class_id_bits'] <= 32
    pools = dict(metadata['pool_classes'])
    pool_audit = dict(audit['pool_heap_classes'])
    allocations = dict(metadata['allocation_returns'])
    allocation_audit = dict(audit['class_allocations'])
    assert all(pool_audit.get(k) == v for k, v in pools.items())
    assert all(allocation_audit.get(k) == v for k, v in allocations.items())
    nodes = {n['start']: n for n in graph['nodes']}
    dispatch = graph['dispatch_table']
    external = {n['address'] for node in nodes.values() for n in node['names']}
    external.update(v for v in dispatch['entries'] if v is not None)
    external.update(e['target'] for e in graph['edges'] if e['target'] is not None)
    image_start, image_end = min(nodes), max(n['end'] for n in nodes.values())
    assert {v for v in external if image_start <= v < image_end} == {v for v in metadata['entries'] if image_start <= v < image_end}
    verified, incoming_checks, blocks_checked = {}, 0, 0

    for certificate in certificates:
        start = certificate['payload']
        node = nodes[start]
        instructions = decode(read(start, node['end'] - start), start)
        by_address = {ins.address: ins for ins in instructions}
        successors = {}
        leaders = {start}
        writes = {}
        for ins in instructions:
            # The architectural CMP/CMN/TST destination is discarded. Ignore
            # Capstone's erroneous operand-write flag on their first source.
            written = ins.regs_write if ins.id in (a.ARM64_INS_CMP, a.ARM64_INS_CMN, a.ARM64_INS_TST, a.ARM64_INS_CCMP, a.ARM64_INS_CCMN) else ins.regs_access()[1]
            writes[ins.address] = {reg(ins, r) for r in written} - {-1}
            result = branch(int.from_bytes(ins.bytes, 'little'), ins.address)
            if result:
                kind, target = result
                assert kind != 'indirect_jump', 'Unknown indirect jump invalidates CFG inference'
                if isinstance(target, int) and start <= target < node['end']:
                    leaders.add(target)
            if result or ins.group(cs.CS_GRP_RET) or ins.id in (a.ARM64_INS_BRK, a.ARM64_INS_HLT):
                if ins.address + 4 < node['end']:
                    leaders.add(ins.address + 4)
            if ins.address in external:
                leaders.add(ins.address)
        boundaries = sorted(leaders) + [node['end']]
        blocks = certificate['blocks']
        assert [(b['start'], b['end']) for b in blocks] == list(zip(boundaries, boundaries[1:]))
        assert len(blocks) <= 1024 and len(instructions) <= 16384
        all_writes = set().union(*writes.values())
        seed = [EMPTY] * 31
        seed[15] = fact(STACK)
        seed[29] = fact(STACK)
        for name, kind, value in ((profile['pool_register'], POOL, 0), (profile.get('dispatch_register'), DISPATCH, 0), (metadata['null_register'], OBJECT, metadata['null_class_id'])):
            if name and name.startswith('x') and int(name[1:]) not in all_writes:
                seed[int(name[1:])] = fact(kind, value)
        seed = tuple(seed)

        def step(state, comparison, ins):
            old = state
            state = list(state)
            ops = ins.operands
            destination = reg(ins, ops[0].reg) if ops and ops[0].type == a.ARM64_OP_REG else -1
            bits = width(ins, ops[0].reg) if destination >= 0 else 0
            produced = EMPTY
            word = int.from_bytes(ins.bytes, 'little')
            move = constant_move(word)
            operation = integer_operation(word)
            if move and destination >= 0:
                kind, number, size, value = move
                assert number == destination
                if kind == 'literal':
                    produced = fact(WORD, value)
                elif kind == 'copy':
                    produced = read_reg(old, ins, ops[1].reg)
                elif kind == 'keep' and old[destination][0] == WORD:
                    produced = fact(WORD, ((old[destination][1] & ~value[1]) | value[0]) & ((1 << size) - 1))
            elif operation and destination >= 0:
                kind, number, size, value = operation
                if kind == 'extract':
                    source = read_reg(old, ins, ops[1].reg)
                    lsb, length = value[1:]
                    if length <= 32:
                        produced = fact(RANGE, (1 << length) - 1)
                        if source[0] == WORD:
                            produced = fact(WORD, (source[1] >> lsb) & ((1 << length) - 1))
                        elif source[0] == HEADER and (lsb, length) == (metadata['class_id_shift'], metadata['class_id_bits']):
                            produced = fact(WORD, source[1])
                else:
                    left = read_reg(old, ins, ops[1].reg)
                    right = supported_operand(old, ins, ops[2], size)
                    if right[0] == WORD:
                        if left[0] == WORD:
                            produced = fact(WORD, (left[1] + right[1] if kind == 'add' else left[1] - right[1]) & ((1 << size) - 1))
                        elif size == 64 and left[0] in (POOL, DISPATCH, STACK):
                            value = signed(left[1]) + (signed(right[1]) if kind == 'add' else -signed(right[1]))
                            if -(1 << 63) <= value < 1 << 63 and (left[0] != STACK or -(1 << 20) <= value <= 1 << 20):
                                produced = fact(left[0], value)
            if ins.id in (a.ARM64_INS_LDR, a.ARM64_INS_LDUR) and len(ops) == 2 and ops[1].type == a.ARM64_OP_MEM and not ins.writeback:
                op = ops[1]
                base = read_reg(old, ins, op.mem.base)
                if not op.mem.index:
                    if base[0] == POOL and bits == 64:
                        relative = signed(base[1]) + op.mem.disp - profile['pool_data_offset']
                        if relative >= 0 and relative % profile['pool_slot_size'] == 0 and relative // profile['pool_slot_size'] in pools:
                            produced = fact(OBJECT, pools[relative // profile['pool_slot_size']])
                    elif base[0] == OBJECT and op.mem.disp == metadata['header_displacement'] and bits in (32, 64):
                        produced = fact(HEADER, base[1])
                elif base[0] == DISPATCH and bits == width(ins, op.mem.index) == 64 and not op.ext and op.shift.type == a.ARM64_SFT_LSL and op.shift.value == 3:
                    index = read_reg(old, ins, op.mem.index)
                    offset = signed(base[1]) + op.mem.disp
                    if index[0] == WORD and offset % 8 == 0 and -(1 << 63) <= offset < 1 << 63:
                        slot = dispatch['origin'] + offset // 8 + signed(index[1])
                        if 0 <= slot < len(dispatch['entries']) and dispatch['entries'][slot] is not None:
                            produced = fact(TARGET, slot, index[1], ins.address)
            stack_writeback = None
            for n, op in enumerate(ops):
                if op.type == a.ARM64_OP_MEM and ins.writeback:
                    base = read_reg(old, ins, op.mem.base)
                    number = reg(ins, op.mem.base)
                    if base[0] == STACK and not op.mem.index and number >= 0 and number != destination:
                        delta = op.mem.disp if n + 1 == len(ops) else ops[n + 1].imm if n + 2 == len(ops) and ops[n + 1].type == a.ARM64_OP_IMM else None
                        if delta is not None and -(1 << 20) <= signed(base[1]) + delta <= 1 << 20:
                            stack_writeback = number, fact(STACK, signed(base[1]) + delta)
            for op in ops:
                if op.type == a.ARM64_OP_MEM and op.access & cs.CS_AC_WRITE:
                    base = read_reg(old, ins, op.mem.base)
                    stack = base[0] == STACK
                    field = base[0] == OBJECT and not ins.writeback and not op.mem.index and op.mem.disp >= metadata['header_displacement'] + 8
                    if not stack and not field:
                        state = [EMPTY if f[0] in (OBJECT, HEADER) else f for f in state]
            if ins.update_flags or ins.id == a.ARM64_INS_MSR or a.ARM64_REG_NZCV in ins.regs_write or (comparison and comparison[0] in writes[ins.address]):
                comparison = ()
            for number in writes[ins.address]:
                state[number] = EMPTY
            if destination >= 0 and destination in writes[ins.address]:
                if produced[0] == UNKNOWN and bits == 32:
                    produced = fact(RANGE, 0xffffffff)
                state[destination] = produced
            if stack_writeback:
                state[stack_writeback[0]] = stack_writeback[1]
            if ins.id == a.ARM64_INS_CMP and len(ops) == 2 and destination >= 0:
                right = supported_operand(state, ins, ops[1], bits)
                if right[0] == WORD:
                    comparison = (destination, bits, right[1] & ((1 << bits) - 1), ins.address)
            if ins.group(cs.CS_GRP_CALL) or ins.group(cs.CS_GRP_INT):
                state, comparison = list(seed), ()
                if ins.id == a.ARM64_INS_BL and ops[0].imm in allocations:
                    state[int(metadata['allocation_result_register'][1:])] = fact(OBJECT, allocations[ops[0].imm])
            return tuple(state), comparison

        def outgoing(block, state, comparison):
            last = by_address[block['end'] - 4]
            result = branch(int.from_bytes(last.bytes, 'little'), last.address)
            if last.group(cs.CS_GRP_RET) or last.id in (a.ARM64_INS_BRK, a.ARM64_INS_HLT):
                return []
            if not result or result[0] in ('call', 'indirect_call'):
                return [(block['end'], state, comparison)] if block['end'] < node['end'] else []
            kind, target = result
            if kind == 'jump':
                return [(target, state, comparison)] if start <= target < node['end'] else []
            compared, bits, equal_value, equality_taken, known = -1, 0, 0, False, None
            if last.id == a.ARM64_INS_B and last.cc in (a.ARM64_CC_EQ, a.ARM64_CC_NE) and comparison:
                compared, bits, equal_value, _ = comparison
                equality_taken = last.cc == a.ARM64_CC_EQ
            elif last.id in (a.ARM64_INS_CBZ, a.ARM64_INS_CBNZ):
                compared, bits = reg(last, last.operands[0].reg), width(last, last.operands[0].reg)
                equality_taken = last.id == a.ARM64_INS_CBZ
            elif last.id in (a.ARM64_INS_TBZ, a.ARM64_INS_TBNZ):
                value = read_reg(state, last, last.operands[0].reg)
                bit = last.operands[1].imm
                if value[0] == WORD:
                    known = (((value[1] >> bit) & 1) == 0) == (last.id == a.ARM64_INS_TBZ)
                elif bit == 0 and reg(last, last.operands[0].reg) >= 0 and state[reg(last, last.operands[0].reg)][0] == OBJECT:
                    known = last.id == a.ARM64_INS_TBNZ
            if compared >= 0:
                value = state[compared]
                if value[0] == WORD:
                    known = ((value[1] & ((1 << bits) - 1)) == equal_value) == equality_taken
                elif value[0] == RANGE and equal_value > value[1]:
                    known = not equality_taken
            results = []
            for taken in (False, True):
                if known is not None and known != taken:
                    continue
                address = target if taken else last.address + 4
                if not start <= address < node['end']:
                    continue
                edge_state = list(state)
                if compared >= 0 and taken == equality_taken:
                    old = state[compared]
                    if bits == 64 or old[0] in (WORD, RANGE) and old[1] <= 0xffffffff:
                        edge_state[compared] = fact(WORD, equal_value)
                results.append((address, tuple(edge_state), comparison))
            return results

        declared, compares, outgoing_edges, inputs = {}, {}, {}, {}
        for block in blocks:
            assert block['entry'] == (block['start'] == start or block['start'] in external)
            values = [EMPTY] * 31
            seen = set()
            for number, kind, value, aux, origin in block['facts']:
                assert 0 <= number < 31 and number not in seen and UNKNOWN < kind <= STACK
                seen.add(number)
                parts = [int(v, 16) for v in (value, aux, origin)]
                assert all(0 <= v <= MASK64 for v in parts)
                assert kind == TARGET or parts[1:] == [0, 0]
                values[number] = fact(kind, *parts)
            declared[block['start']] = tuple(values)
            compares[block['start']] = tuple(block['compare'])
            assert not compares[block['start']] or len(compares[block['start']]) == 4
            if compares[block['start']]:
                number, bits, value, site = compares[block['start']]
                assert 0 <= number < 31 and bits in (32, 64) and 0 <= value < 1 << bits and site in by_address
            if block['entry']:
                inputs.setdefault(block['start'], []).append((seed, ()))
            if not block['reachable']:
                assert not block['facts'] and not block['compare']
                continue
            state, comparison = tuple(values), compares[block['start']]
            for address in range(block['start'], block['end'], 4):
                ins = by_address[address]
                if address in claims:
                    assert ins.id == a.ARM64_INS_BLR
                    value = read_reg(state, ins, ins.operands[0].reg)
                    claim = claims[address]
                    assert value[0] == TARGET
                    assert (claim['table_index'], claim['index'], claim['load'], claim['snapshot_target']) == (value[1], signed(value[2]), value[3], dispatch['entries'][value[1]])
                    assert claim['proof'] and all(p in by_address for p in claim['proof']) and value[3] in claim['proof']
                    verified[address] = claim
                state, comparison = step(state, comparison, ins)
            edges = outgoing(block, state, comparison)
            outgoing_edges[block['start']] = edges
            for address, incoming, flags in edges:
                inputs.setdefault(address, []).append((incoming, flags))
            blocks_checked += 1
        reachable, queue = set(), deque(b['start'] for b in blocks if b['entry'])
        while queue:
            address = queue.popleft()
            if address in reachable:
                continue
            reachable.add(address)
            assert address in outgoing_edges
            queue.extend(e[0] for e in outgoing_edges[address])
        assert reachable == {b['start'] for b in blocks if b['reachable']}
        for address in reachable:
            for incoming, flags in inputs[address]:
                assert all(entails(source, dest) for source, dest in zip(incoming, declared[address])), (hex(address), incoming, declared[address])
                assert not compares[address] or compares[address] == flags
                incoming_checks += 1
    assert set(verified) == set(claims), 'Missing or duplicate receiver certificate'
    return {'receiver_claims_checked': len(verified), 'receiver_blocks_checked': blocks_checked,
            'receiver_incoming_edges_checked': incoming_checks, 'receiver_pool_class_inputs_checked': len(pools),
            'receiver_allocation_inputs_checked': len(allocations)}
