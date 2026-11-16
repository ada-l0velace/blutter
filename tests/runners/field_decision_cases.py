"""Authored short-circuit Boolean diamonds and their failure controls."""
import io
from field_decisions import expected_notes, check_stream


def run_cases(run):
    prefix = ['stp x29, x30, [x15, #-16]!', 'mov x29, x15',
              'sub x15, x15, #0x100', 'stur x22, [x29, #-8]', 'mov x0, x22', 'bl 0x11000',
              'bl 0x5000', 'bl 0x12000']
    start = 0x1000 + len(prefix)*4
    optional = ['stur x0, [x29, #-16]', f'cbz x1, {start+16:#x}',
                'mov x0, x22', 'bl 0x12000', 'ldur x2, [x29, #-16]']
    branch = start + (len(optional)+2)*4
    helpers = {pc: ['ret'] for pc in (0x11000, 0x12000, 0x13000, 0x14000, 0x15000, 0x16000)}
    helpers.update({0x17000: ['brk #0', 'nop'], 0x17100: ['nop', 'ret'],
                    0x4000: ['ret'], 0x5000: prefix[:6] + ['bl 0x6000', 'b 0x14000']})
    body = ['ldur w3, [x2, #7]', 'add x3, x3, x28, lsl #32',
            f'tbnz w3, #4, {branch+36:#x}',
            'ldur w4, [x2, #11]', 'add x4, x4, x28, lsl #32', 'cmp w4, w22',
            'add x6, x22, #32', 'add x7, x22, #48', 'csel x8, x6, x7, ne',
            'mov x9, x8', f'b {branch+40:#x}', 'add x9, x22, #48',
            'stur x9, [x29, #-24]']

    def case(name, changes=None, want=False, after=(), tail=()):
        instructions = body.copy()
        for index, replacement in (changes or {}).items():
            instructions[index] = replacement
        graph = run('decision-' + name, prefix + optional + instructions + list(tail) +
                    ['mov x0, x22', 'b 0x14000'] + list(after), helpers,
                    async_contracts=True, completions='valid', future_bindings='valid', saved_refs='fields')
        assert len(graph['field_decisions']) == int(want), (name, graph['field_decisions'])
        return graph

    graph = case('base', want=True)
    decision, = graph['field_decisions']
    assert decision == dict(branch_use=0, load=branch+4, site=branch+40,
                            offset=12, fp_offset=-24, register=9, on_set=True, non_null_true=True)
    case('inverted-bit', {2: body[2].replace('tbnz', 'tbz')}, want=True)
    inverted = case('null-equal', {8: body[8].replace('ne', 'eq')}, want=True)
    assert not inverted['field_decisions'][0]['non_null_true']
    case('swapped-constants', {6: 'add x6, x22, #48', 7: 'add x7, x22, #32'}, want=True)
    for name, index, word in [
        ('wrong-owner', 3, 'ldur w4, [x1, #11]'),
        ('owner-clobbered', 0, 'ldur w2, [x2, #7]'),
        ('wrong-second-width', 3, 'ldur x4, [x2, #11]'),
        ('excluded-slot', 3, 'ldur w4, [x2, #15]'),
        ('wrong-null-register', 5, 'cmp w4, w21'),
        ('wrong-comparison-width', 5, 'cmp x4, x22'),
        ('wrong-constant', 6, 'add x6, x22, #64'),
        ('constant-flags', 6, 'adds x6, x22, #32'),
        ('constant-overwrite', 7, 'add x6, x22, #48'),
        ('unproved-fallback', 11, 'add x9, x22, #32'),
        ('wrong-select', 8, 'csel x8, x6, x5, ne'),
        ('wrong-condition', 8, 'csel x8, x6, x7, gt'),
        ('wrong-copy', 9, 'mov x9, x4'),
        ('wrong-join', 10, f'b {branch+44:#x}'),
        ('wrong-store', 12, 'stur x8, [x29, #-24]'),
        ('partial-store', 12, 'stur w9, [x29, #-24]'),
        ('unaligned-store', 12, 'stur x9, [x29, #-23]'),
    ]:
        case(name, {index: word})
    clobbered = case('owner-replaced', {
        0: 'ldur w2, [x2, #7]', 1: 'add x2, x2, x28, lsl #32',
        2: body[2].replace('w3', 'w2')})
    assert len(clobbered['field_branch_uses']) == 1
    null_clobbered = case('null-replaced', {
        0: 'ldur w22, [x2, #7]', 1: 'add x22, x22, x28, lsl #32',
        2: body[2].replace('w3', 'w22')})
    for index in (1, 3, 6, 9, 10):
        case(f'extra-edge-{index}', after=[f'b {branch+index*4:#x}'])
    expected = expected_notes(graph)
    (site, comment), = expected
    text = f'// {comment}\n// {site:#x}: stur x9, [x29, #-24]\n'.replace('\\n', '\n')
    assert check_stream(io.StringIO(text), expected) == expected
    for forged in [text.replace('clear', 'set'), text.replace(f'{site:#x}', f'{site+4:#x}')]:
        try:
            check_stream(io.StringIO(forged), expected)
        except AssertionError:
            pass
        else:
            raise AssertionError('Forged decision comment accepted')

    # A later branch must consume the same saved Boolean on every path.
    from decision_branch_uses import expected_notes as use_notes, check_stream as use_stream
    tail_start = branch + 44
    later = tail_start + 8
    tail = ['bl 0x4000', 'ldur x1, [x29, #-24]',
            f'tbnz w1, #4, {later+8:#x}', 'nop', 'nop']
    forwarded = case('saved-use', want=True, tail=tail)
    use, = forwarded['decision_branch_uses']
    assert (use['site'],use['true_target'],use['false_target']) == (later,later+4,later+8)
    for name, replacement in [
        ('overwritten', 'stur x22, [x29, #-24]'),
        ('partial-overwrite', 'stur w22, [x29, #-20]'),
    ]:
        killed = case(name, want=True, tail=[replacement]+tail)
        assert not killed['decision_branch_uses']
    adjacent = case('adjacent-spill', want=True,
                    tail=['stur x22, [x29, #-32]']+tail)
    assert len(adjacent['decision_branch_uses']) == 1
    wrong_bit = case('wrong-value-bit', want=True, tail=[tail[0],tail[1],
                     tail[2].replace('#4,','#3,')]+tail[3:])
    assert not wrong_bit['decision_branch_uses']
    entry = case('branch-entry', want=True, tail=tail, after=[f'b {later:#x}'])
    assert not entry['decision_branch_uses']
    copied_tail = ['ldur x1, [x29, #-24]', 'stur x1, [x29, #-32]',
                   'bl 0x4000', 'ldur x2, [x29, #-32]',
                   f'tbz w2, #4, {tail_start+24:#x}', 'nop', 'nop']
    copied = case('copied-spill', want=True, tail=copied_tail)
    assert len(copied['decision_branch_uses']) == 1
    expected = use_notes(forwarded)
    (pc, comment), = expected
    text = f'// {comment}\n// {pc:#x}: tbnz w1, #4, {later+8:#x}\n'
    assert use_stream(io.StringIO(text), expected) == expected
