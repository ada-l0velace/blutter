"""Check conditional array-result invariants against original ARM64 words.

This checks each declared incoming invariant; it does not run a fixed-point
solver or trust a function name. Caller element facts are checked separately.
"""
import capstone as cs
from capstone import arm64 as a
from check_snapshot_annotations import branch, constant_move
from check_call_effects import number, size, LOADS

EMPTY = (0, 0, 0)


def check_array_return(claim, code, frames, metadata, audit, nonreturning):
    layout = metadata.get('array_body_contract', [])
    assert layout and layout == audit.get('array_body_contract')
    assert metadata.get('word_return_register') == audit.get('word_return_register') == 'x0'
    assert layout[3] in (4, 8)
    if layout[3] == 4:
        assert metadata.get('heap_bits_register') == audit.get('heap_bits_register') == 'x28'
    array_slot, index_slot = claim['array_sp_offset'], claim['index_sp_offset']
    assert all(type(v) is int and 0 <= v <= 248 and v % 8 == 0 for v in (array_slot, index_slot)) and array_slot != index_slot
    assert claim['index_representation'] == 'smi' and type(claim['index_min']) is type(claim['index_max']) is int
    assert (claim['index_min'], claim['index_max']) == (0, 31)
    by_site = {i.address: i for i in code}
    states = {}
    assert 0 < len(claim['states']) <= len(code)
    for site, registers in claim['states']:
        assert type(site) is int and site in by_site and site in frames and site not in states
        state, seen = [EMPTY] * 31, set()
        for r, kind, left, right in registers:
            assert all(type(v) is int for v in (r, kind, left, right))
            assert 0 <= r < 31 and r not in seen and 1 <= kind <= 6
            assert 0 <= left <= 248 and left % 8 == 0
            assert right == 0 if kind <= 3 else right == index_slot and left != index_slot
            assert kind not in (2, 3) or left == index_slot
            assert kind != 1 or left != index_slot
            seen.add(r)
            state[r] = (kind, left, right)
        states[site] = tuple(state)
    start = code[0].address
    assert start in states and states[start] == (EMPTY,) * 31
    pending, reached, returns = [start], set(), 0
    while pending:
        site = pending.pop()
        if site in reached:
            continue
        reached.add(site)
        ins, old = by_site[site], states[site]
        word, ops = int.from_bytes(ins.bytes, 'little'), ins.operands
        state = list(old)
        flags = ins.mnemonic in ('cmp', 'cmn', 'tst', 'ccmp', 'ccmn')
        for r in ins.regs_write if flags else ins.regs_access()[1]:
            n = number(ins, r)
            if n >= 0:
                state[n] = EMPTY
        transfer = branch(word, site)
        if transfer and transfer[0] in ('call', 'indirect_call'):
            target = transfer[1]
            if transfer[0] == 'indirect_call':
                r = (word >> 5) & 31
                assert r < 31 and frames[site][0][r][0] == 6
                target = frames[site][0][r][1]
            assert target in nonreturning, 'Array relation crosses a returning call'
            continue
        if ins.id == a.ARM64_INS_RET:
            assert old[0] == (6, array_slot, index_slot), 'Array relation does not hold on every normal return'
            returns += 1
            continue
        if ins.id in (a.ARM64_INS_BRK, a.ARM64_INS_HLT):
            continue
        move = constant_move(word)
        if move and move[0] == 'copy':
            _, dst, bits, src = move
            if src < 31 and (bits == 64 or old[src][0] in (2, 3)) and dst < 31:
                state[dst] = old[src]
        # SBFM Xd,Xn,#1,#31 is the SBFX Xd,Xn,#1,#31 alias.
        if word & 0xfffffc00 == 0x93417c00:
            dst, src = word & 31, (word >> 5) & 31
            if dst < 31 and src < 31 and old[src] == (2, index_slot, 0):
                state[dst] = (3, index_slot, 0)
        # ADD Xd,Xn,Xm,LSL #shift; excludes flag-setting/extended forms.
        if word & 0xffe00000 == 0x8b000000:
            dst, left, right, shift = word & 31, (word >> 5) & 31, (word >> 16) & 31, (word >> 10) & 63
            if max(dst, left, right) < 31:
                if old[left][0] == 1 and old[right] == (3, index_slot, 0) and shift == (2 if layout[3] == 4 else 3):
                    state[dst] = (4, old[left][1], index_slot)
                if layout[3] == 4 and old[left][0] == 5 and right == 28 and shift == 32:
                    state[dst] = (6, old[left][1], old[left][2])
        for op in ops:
            if op.type != a.ARM64_OP_MEM:
                continue
            base = number(ins, op.mem.base)
            stack = base >= 0 and frames[site][0][base][0] == 1 and not op.mem.index
            if ins.mnemonic not in LOADS:
                assert stack, 'Array relation permits a heap write'
                continue
            if ins.mnemonic not in ('ldr', 'ldur') or len(ops) != 2 or ins.writeback or op.mem.index:
                continue
            dst, width = number(ins, ops[0].reg), size(ins, ops[0].reg)
            if dst < 0:
                continue
            if stack and width == 8:
                slot = frames[site][0][base][1] + op.mem.disp
                if 0 <= slot <= 248 and slot % 8 == 0:
                    state[dst] = (2 if slot == index_slot else 1, slot, 0)
            elif base >= 0 and old[base][0] == 4 and op.mem.disp == layout[2] and width == layout[3]:
                state[dst] = (5 if width == 4 else 6, old[base][1], old[base][2])
        successors = [site+4]
        if transfer:
            assert transfer[0] not in ('call', 'indirect_call', 'indirect_jump')
            successors = [transfer[1]]
            if word & 0xfc000000 != 0x14000000:
                successors.append(site+4)
            # Bounded Smi inputs have bit zero clear, in W and X views.
            if word & 0x7e000000 == 0x36000000 and not word & 0x80f80000:
                r = word & 31
                if r < 31 and old[r] == (2, index_slot, 0):
                    successors = [site+4 if word & 0x01000000 else transfer[1]]
        for target in successors:
            assert target in states, 'Missing array-return invariant'
            assert all(want == EMPTY or got == want for got, want in zip(state, states[target])), 'Forged array-return invariant'
            pending.append(target)
    assert reached == states.keys() and returns, 'Unreachable array state or no normal return'
    return len(reached)
