"""Check conditional leaf length relations from original ARM64 encodings.

The checker has no dependency on the producer IR. Runtime layouts come from the
separate numerical SDK audit; a function name is not evidence of this relation.
"""
from check_snapshot_annotations import constant_move


def length_register_writes(code):
    """Use only after validating the leaf's complete positive instruction subset."""
    result = 0
    for ins in code:
        word = int.from_bytes(ins.bytes, 'little')
        if word not in (0xd503201f, 0xd65f03c0):
            result |= 1 << (word & 31)
    return result


def checked_length_layout(graph, audit):
    layout = graph['receiver_metadata'].get('array_length_layout', [])
    if not layout:
        return None
    assert graph.get('format', 4) >= 16 and len(layout) == 4
    assert all(type(v) is int for v in layout) and layout == audit.get('array_length_layout')
    cid, offset, width, shift = layout
    assert 0 < cid < 1 << 32 and 0 <= offset <= (1 << 20) - 8 and width in (4, 8) and shift == 1
    return tuple(layout)


def check_array_length(claim, code, graph, audit):
    layout = checked_length_layout(graph, audit)
    assert layout is not None and graph['receiver_metadata'].get('word_return_register') == audit.get('word_return_register') == 'x0'
    cid, offset, width, shift = layout
    fields = {'array_sp_offset', 'array_class_id', 'result_register', 'result_representation', 'heap_effect', 'may_fault', 'proof'}
    if graph.get('format', 4) >= 17:
        fields.add('written_registers')
        assert type(claim.get('written_registers')) is int and claim['written_registers'] == length_register_writes(code)
    assert set(claim) == fields
    slot = claim['array_sp_offset']
    assert type(slot) is int and 0 <= slot <= 248 and slot % 8 == 0
    assert type(claim['array_class_id']) is int and claim['array_class_id'] == cid
    assert claim['result_register'] == 'x0'
    assert claim['result_representation'] == ('zero_extended_smi' if width == 4 else 'smi')
    assert claim['heap_effect'] == 'read_only' and claim['may_fault'] is True
    assert 3 <= len(code) <= 32
    proof = claim['proof']
    assert type(proof) is list and all(type(v) is int for v in proof) and proof == [code[0].address+n*4 for n in range(len(code))]
    # Symbolic relations: entry stack, untyped input slot, selected length.
    state = [None] * 31
    state[15] = ('stack', 0)
    forbidden = {15, 21, 22, 26, 27, 28, 29, 30, 31}
    for n, ins in enumerate(code):
        assert ins.size == 4 and ins.address == proof[n]
        word = int.from_bytes(ins.bytes, 'little')
        if word == 0xd503201f:
            continue
        if word == 0xd65f03c0:
            assert n+1 == len(code) and state[0] == ('length', slot), 'Length relation fails at normal return'
            return len(code)
        dst, base = word & 31, (word >> 5) & 31
        assert dst not in forbidden, 'Length helper changes frame/reserved registers'
        # Unsigned-immediate scalar GPR LDR only (no SIMD or sign extension).
        scaled = word & 0xffc00000
        # Unscaled LDUR only; pre/post/unprivileged modes remain excluded.
        unscaled = word & 0xffe00c00
        if scaled in (0xb9400000, 0xf9400000) or unscaled in (0xb8400000, 0xf8400000):
            size = 8 if word >> 30 == 3 else 4
            displacement = ((word >> 10) & 0xfff) * size if scaled in (0xb9400000, 0xf9400000) else (word >> 12) & 0x1ff
            if scaled not in (0xb9400000, 0xf9400000) and displacement & 0x100:
                displacement -= 0x200
            value = state[base] if base < 31 else None
            if value == ('stack', 0) and size == 8 and 0 <= displacement <= 248 and displacement % 8 == 0:
                state[dst] = ('input', displacement)
            else:
                assert value and value[0] == 'input' and size == width and displacement == offset, 'Unproved length memory access'
                state[dst] = ('length', value[1])
        else:
            move = constant_move(word)
            assert move and move[0] == 'copy' and move[3] < 31, 'Length relation permits an unsupported effect or transfer'
            _, dst, bits, source = move
            value = state[source]
            state[dst] = value if bits == 64 or width == 4 and value and value[0] == 'length' else None
    raise AssertionError('Length helper has no checked normal return')
