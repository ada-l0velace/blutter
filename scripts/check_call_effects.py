"""Validate caller-frame preservation certificates from original machine words.

Each instruction's declared pre-state must hold for every incoming edge. This
does not run the producer's worklist or accept inferred effects as SDK facts.
"""
import capstone as cs
from capstone import arm64 as a

from check_snapshot_annotations import branch, constant_move, integer_operation


REGISTER_ONLY = set(('nop mov movz movn movk add sub adds subs and ands orr eor bic mvn neg mul madd msub '
                     'sdiv udiv lsl lsr asr ubfx sbfx sxtw uxtw cmp cmn tst ccmp ccmn csel csinc csinv '
                     'csneg cset csetm cinc cneg adr adrp fmov fadd fsub fmul fdiv fneg fabs fcmp fcmpe '
                     'fcvt fcvtzs fcvtzu scvtf ucvtf').split())
LOADS = set('ldr ldur ldrb ldurb ldrh ldurh ldrsb ldursb ldrsh ldursh ldrsw ldursw ldp ldnp ldpsw'.split())
STORES = set('str stur stp strb sturb strh sturh'.split())
ZERO = (0, 0)


def number(ins, r):
    name = ins.reg_name(r)
    if name in ('fp', 'lr'):
        return 29 if name == 'fp' else 30
    return int(name[1:]) if name.startswith(('x', 'w')) and name[1:].isdigit() else -1


def size(ins, r):
    name = ins.reg_name(r)
    if name in ('fp', 'lr', 'xzr') or name.startswith('x'):
        return 8
    return {'w': 4, 'q': 16, 'd': 8, 's': 4, 'h': 2, 'b': 1}.get(name[:1], 0)


def checked_nonreturning_calls(graph, audit):
    rows = graph['receiver_metadata'].get('nonreturning_calls', [])
    assert len(rows) <= 1 and (graph.get('format', 4) >= 11 or not rows)
    calls = dict(rows)
    assert len(calls) == len(rows)
    for entry, contract in calls.items():
        assert type(entry) is int and 0 <= entry < 1 << 64 and entry % 4 == 0
        assert contract == 'range_error_without_fpu'
        assert dict(audit.get('nonreturning_calls', [])).get(entry) == contract, 'Non-return contract lacks independent VM audit'
    for field in ('allocation_returns', 'frame_preserving_calls'):
        assert not calls.keys() & dict(graph['receiver_metadata'].get(field, [])).keys()
    return calls


def check_call_effects(graph, read, decode, trusted, audit):
    certificates = graph.get('call_effects', [])
    assert graph.get('format', 4) >= 9 or not certificates
    assert len(certificates) <= 16384
    nodes = {n['start']: n for n in graph['nodes']}
    effects = {c['payload']: c for c in certificates}
    assert len(effects) == len(certificates) and not effects.keys() & trusted
    nonreturning = checked_nonreturning_calls(graph, audit)
    assert not effects.keys() & nonreturning.keys()
    assert not effects or graph['profile']['pool_register'] == 'x27' and graph['profile']['thread_register'] == 'x26'
    instructions_checked = 0
    contract = graph['receiver_metadata'].get('leaf_math_contract', [])
    assert not contract or graph.get('format', 4) >= 9 and len(contract) == 4 and contract == audit.get('leaf_math_contract')
    if contract:
        assert all(type(v) is int for v in contract)
        assert all(0 <= v < 32768 and v % 8 == 0 for v in contract[:3]) and 0 <= contract[3] <= 65535
    pool_entries = {(slot, field): target for slot, field, target in audit.get('pool_code_entries', [])}
    bodies_enabled = graph.get('format', 4) >= 10
    body_rows = graph['receiver_metadata'].get('allocation_body_bounds', [])
    body_bounds = {entry: (lo, hi) for entry, lo, hi in body_rows}
    assert len(body_rows) == len(body_bounds) and (bodies_enabled or not body_bounds)
    audited_bounds = {entry: (lo, hi) for entry, lo, hi in audit.get('allocation_body_bounds', [])}
    allocations = dict(graph['receiver_metadata']['allocation_returns'])
    for entry, (lo, hi) in body_bounds.items():
        assert entry in allocations and type(lo) is type(hi) is int and 7 <= lo <= hi <= 1 << 20
        assert audited_bounds.get(entry) == (lo, hi)
    array = graph['receiver_metadata'].get('array_body_contract', [])
    if array:
        assert bodies_enabled and len(array) == 5 and array == audit.get('array_body_contract')
        assert all(type(v) is int for v in array)
        assert array[0] in allocations and 0 <= array[1] <= 14 and 7 <= array[2] <= 1 << 20 and array[3] in (4, 8) and array[4] == 1
    masks = dict(graph['receiver_metadata'].get('preserved_call_registers', []))
    result_reg = int(graph['receiver_metadata']['allocation_result_register'][1:])
    assert 0 <= result_reg < 31

    def alias(kind, offset, *bounds):
        assert type(kind) is int and type(offset) is int and 1 <= kind <= (8 if bodies_enabled else 6)
        if kind == 7:
            assert len(bounds) == 2 and all(type(v) is int for v in bounds)
            assert abs(offset) <= 1 << 20 and 7 <= bounds[0] <= bounds[1] <= 1 << 20
            return kind, offset, *bounds
        assert not bounds
        if kind == 8:
            assert -(1 << 63) <= offset < 1 << 63
            return kind, offset
        assert abs(offset) <= 1 << 20 if kind in (1, 4) else offset == 0 if kind in (2, 3) else 0 <= offset < (1 << 63)
        return kind, offset

    for start, certificate in effects.items():
        assert type(start) is int and start in nodes
        end = nodes[start]['end']
        assert 0 < end - start <= 4096 and (end - start) % 4 == 0
        depth = certificate['depth']
        assert type(depth) is int and 1 <= depth <= 8
        code = decode(read(start, end - start), start)
        assert len(code) * 4 == end - start and all(i.address == start + n * 4 and i.size == 4 for n, i in enumerate(code))
        by_site = {i.address: i for i in code}
        all_writes = {number(i, r) for i in code for r in i.regs_access()[1]}
        assert not all_writes & {21, 22, 26, 27, 28}, 'Callee changes reserved Dart registers'
        pool_fixed = graph['profile']['pool_register'] == 'x27' and 27 not in all_writes
        thread_fixed = graph['profile']['thread_register'] == 'x26' and 26 not in all_writes
        states = {}
        assert 0 < len(certificate['states']) <= len(code)
        for site, regs, slots in certificate['states']:
            assert type(site) is int and site in by_site and site not in states
            values = [ZERO] * 31
            seen = set()
            for r, kind, offset, *bounds in regs:
                assert type(r) is int and 0 <= r < 31 and r not in seen
                seen.add(r)
                values[r] = alias(kind, offset, *bounds)
            memory = {}
            assert len(slots) <= 128
            for offset, kind, value, *bounds in slots:
                assert type(offset) is int and -(1 << 20) <= offset <= -8 and offset not in memory
                memory[offset] = alias(kind, value, *bounds)
            states[site] = (tuple(values), memory)

        seed = [ZERO] * 31
        seed[15], seed[29], seed[30] = (1, 0), (2, 0), (3, 0)
        if pool_fixed:
            seed[27] = (4, 0)

        def entails(actual, declared):
            return all(want == ZERO or got == want for got, want in zip(actual[0], declared[0])) and all(actual[1].get(k) == v for k, v in declared[1].items())

        assert start in states and entails((seed, {}), states[start])
        reached, pending, returns = set(), [start], 0
        while pending:
            site = pending.pop()
            if site in reached:
                continue
            reached.add(site)
            instructions_checked += 1
            assert instructions_checked <= 2000000
            ins = by_site[site]
            word = int.from_bytes(ins.bytes, 'little')
            ops = ins.operands
            old, before_slots = states[site]
            state, slots = list(old), dict(before_slots)
            # Reviewed LeafRuntimeScope(preserve_registers=false), unary round
            # ABI. Match the full C frame, exact thread fields and restoration;
            # a BLR loaded from a similarly named field alone is insufficient.
            leaf = False
            if contract and thread_fixed and site+52 <= end:
                entry_offset, tag_offset, limit_offset, dart_tag = contract
                expected = [0xa9bf79fd, 0xaa0f03fd, 0x927cedef, 0x910001ff,
                            0xf9400350 | entry_offset//8 << 10, 0xf9000350 | tag_offset//8 << 10,
                            0xd63f0200, 0xd2800010 | dart_tag << 5, 0xf9000350 | tag_offset//8 << 10,
                            0xf9400350 | limit_offset//8 << 10, 0xd140061f, 0xaa1d03ef, 0xa8c179fd]
                leaf = all(int.from_bytes(by_site[site+n*4].bytes, 'little') == v for n, v in enumerate(expected))
            if leaf:
                assert old[15][0] == 1 and old[15][1] >= -(1 << 20)+16
                state = [ZERO] * 31
                for r in (15, 29, 30):
                    state[r] = old[r]
                if pool_fixed:
                    state[27] = (4, 0)
                assert site+52 in states and entails((state, slots), states[site+52])
                pending.append(site+52)
                instructions_checked += 12
                continue
            assert not any(ins.reg_name(r) in ('sp', 'wsp') for r in ins.regs_access()[1]), 'Unreviewed C stack update'
            flags = ins.mnemonic in ('cmp', 'cmn', 'tst', 'ccmp', 'ccmn')
            writes = {number(ins, r) for r in (ins.regs_write if flags else ins.regs_access()[1])} - {-1}
            for r in writes:
                state[r] = ZERO
            transfer = branch(word, site)
            is_branch = transfer and transfer[0] not in ('call', 'indirect_call', 'indirect_jump')
            if transfer and transfer[0] in ('call', 'indirect_call'):
                assert old[15][0] == 1 and old[15][1] <= -16
                if transfer[0] == 'call':
                    target = transfer[1]
                else:
                    target_reg = (word >> 5) & 31
                    assert target_reg < 31 and old[target_reg][0] == 6
                    target = old[target_reg][1]
                if target in nonreturning:
                    continue  # No normal successor and no returning effect for this entry.
                assert not any(v[0] == 1 for r, v in enumerate(old) if r not in (15, 29))
                assert target in trusted or target in effects and effects[target]['depth'] < depth
                state = [ZERO] * 31
                state[15], state[29] = old[15], old[29]
                if pool_fixed:
                    state[27] = (4, 0)
                if bodies_enabled:
                    for r in range(31):
                        if masks.get(target, 0) & (1 << r) and r not in (15, 29, 30):
                            if old[r][0] != 7 or old[r][1] == 0:
                                state[r] = old[r]
                    slots = {k: v for k, v in slots.items() if v[0] != 7 or v[1] == 0}
                    if target in body_bounds:
                        state[result_reg] = (7, 0, *body_bounds[target])
                    if array and target == array[0]:
                        length = old[array[1]]
                        if length[0] == 8 and length[1] >= 0 and not length[1] & 1 and length[1] >> array[4] <= ((1 << 20)-array[2])//array[3]:
                            state[result_reg] = (7, 0, array[2], array[2]+(length[1] >> array[4])*array[3])
            elif word & 0xfffffc1f == 0xd65f0000:  # RET Xn: only the original LR qualifies.
                assert (word >> 5) & 31 == 30
                assert old[15] == (1, 0) and old[29] == (2, 0) and old[30] == (3, 0)
                returns += 1
                continue
            elif ins.id in (a.ARM64_INS_BRK, a.ARM64_INS_HLT):
                continue
            elif is_branch:
                pass
            else:
                assert not transfer, 'Unreviewed indirect call/jump'
                memory = False
                for j, op in enumerate(ops):
                    if op.type != a.ARM64_OP_MEM:
                        continue
                    memory = True
                    load, store = ins.mnemonic in LOADS, ins.mnemonic in STORES
                    assert load or store
                    # Reject atomic/exclusive/unprivileged forms independently
                    # of operand access flags and the producer's opcode list.
                    pair = ins.mnemonic in ('stp', 'ldp', 'ldnp', 'ldpsw')
                    assert word & 0x3a000000 == 0x28000000 if pair else (
                        word & 0x3b000000 == 0x39000000 or word & 0x3b200000 == 0x38000000 or word & 0x3b200c00 == 0x38200800)
                    assert j == (2 if pair else 1)
                    base = number(ins, op.mem.base)
                    stack = base >= 0 and old[base][0] == 1 and not op.mem.index
                    at = old[base][1] + op.mem.disp if stack else 0
                    width = 1 if ins.mnemonic in ('strb', 'sturb') else 2 if ins.mnemonic in ('strh', 'sturh') else size(ins, ops[0].reg)
                    assert not pair or size(ins, ops[1].reg) == width
                    assert not pair or not load or ops[0].reg != ops[1].reg
                    if ins.writeback:
                        assert stack and base == 15
                        assert all(number(ins, ops[part].reg) != base for part in range(2 if pair else 1))
                        post = j + 2 == len(ops) and ops[j+1].type == a.ARM64_OP_IMM
                        assert post or j + 1 == len(ops)
                        delta = ops[j+1].imm if post else op.mem.disp
                        assert abs(delta) <= 1 << 20
                        state[15] = (1, old[15][1] + delta)
                    if store:
                        count = width * (2 if pair else 1)
                        if base >= 0 and old[base][0] == 7 and not op.mem.index and not ins.writeback and width:
                            at_heap = old[base][1]+op.mem.disp
                            if old[base][2] <= at_heap <= old[base][3]-count:
                                continue
                        assert stack and width and old[15][0] == state[15][0] == 1
                        assert min(old[15][1], state[15][1]) <= at <= -count
                        slots = {k: v for k, v in slots.items() if not (at < k+8 and k < at+count)}
                        if width == 8:
                            for part in range(2 if pair else 1):
                                r = number(ins, ops[part].reg)
                                if r >= 0 and old[r] != ZERO:
                                    slots[at+part*8] = old[r]
                    elif stack and width == 8 and ins.mnemonic in ('ldr', 'ldur', 'ldp', 'ldnp'):
                        for part in range(2 if pair else 1):
                            r = number(ins, ops[part].reg)
                            if r >= 0 and at+part*8 in slots:
                                state[r] = slots[at+part*8]
                    elif not ins.writeback and not op.mem.index and ins.mnemonic in ('ldr', 'ldur') and size(ins, ops[0].reg) == 8 and base >= 0 and number(ins, ops[0].reg) >= 0:
                        source, dst = old[base], number(ins, ops[0].reg)
                        if source[0] == 4 and graph['profile']['pool_slot_size'] == 8:
                            offset = source[1]+op.mem.disp-graph['profile']['pool_data_offset']
                            if offset >= 0 and offset % 8 == 0 and offset//8 < graph['profile'].get('pool_length', 0):
                                state[dst] = (5, offset//8)
                        elif source[0] == 5 and (source[1], op.mem.disp) in pool_entries:
                            state[dst] = (6, pool_entries[source[1], op.mem.disp])
                if not memory:
                    assert ins.mnemonic in REGISTER_ONLY
                    dst = number(ins, ops[0].reg) if ops and ops[0].type == a.ARM64_OP_REG else -1
                    if dst >= 0 and dst in writes and size(ins, ops[0].reg) == 8:
                        if ins.id == a.ARM64_INS_MOV and len(ops) == 2 and ops[1].type == a.ARM64_OP_REG and size(ins, ops[1].reg) == 8 and number(ins, ops[1].reg) >= 0:
                            state[dst] = old[number(ins, ops[1].reg)]
                        # Decode ADD/SUB immediate using original bits.
                        if word & 0xff000000 in (0x91000000, 0xd1000000) and not word & (1 << 22):
                            src = (word >> 5) & 31
                            if src < 31 and old[src][0] in (1, 4):
                                delta = (word >> 10) & 0xfff
                                state[dst] = (old[src][0], old[src][1] + (-delta if word & (1 << 30) else delta))
                    if bodies_enabled and dst >= 0 and dst in writes:
                        def word_value(value, bits):
                            value &= (1 << bits)-1
                            return (8, value-(1 << 64) if value >> 63 else value)
                        def read_value(r, bits):
                            value = old[r] if r < 31 else (8, 0)
                            return word_value(value[1], bits) if value[0] == 8 else value if bits == 64 else ZERO
                        move = constant_move(word)
                        operation = integer_operation(word)
                        if move:
                            kind, dest, bits, value = move
                            assert dest == dst
                            state[dst] = ZERO
                            if kind == 'literal':
                                state[dst] = word_value(value, bits)
                            elif kind == 'copy':
                                state[dst] = read_value(value, bits)
                            elif kind == 'keep' and old[dst][0] == 8:
                                state[dst] = word_value((old[dst][1] & ~value[1]) | value[0], bits)
                        elif operation and operation[0] in ('add', 'sub') and operation[3][1] == 'immediate':
                            kind, dest, bits, (src, _, delta) = operation
                            assert dest == dst
                            value = read_value(src, bits)
                            state[dst] = ZERO
                            change = -delta if kind == 'sub' else delta
                            if value[0] == 8:
                                state[dst] = word_value(value[1]+change, bits)
                            elif bits == 64 and value[0] in (1, 4, 7):
                                state[dst] = (value[0], value[1]+change, *value[2:])
            assert state[15][0] == 1 and -(1 << 20) <= state[15][1] <= 0 and len(slots) <= 128
            assert all(v[0] not in (1, 4, 7) or abs(v[1]) <= 1 << 20 for v in state)
            slots = {k: v for k, v in slots.items() if k >= state[15][1]}
            successors = [site + 4]
            if is_branch:
                successors = [transfer[1]]
                if word & 0xfc000000 != 0x14000000:  # Conditional branches include fallthrough.
                    successors.append(site + 4)
            for next_site in successors:
                assert next_site in states, 'Missing callee effect state or out-of-payload transfer'
                assert entails((state, slots), states[next_site]), 'Forged callee frame/return invariant'
                pending.append(next_site)
        assert reached == states.keys() and returns, 'Unreachable effect state or no proved normal return'
    return set(effects), instructions_checked
