"""Captured values through reviewed allocation, with independent failure controls."""
import copy
import io
from captured_field_values import check_captures, check_stream, note, validate_structure
from query_captured_fields import query, render


def run_cases(run):
    prefix = ['stp x29, x30, [x15, #-16]!', 'mov x29, x15', 'sub x15, x15, #0x100',
        'stur x22, [x29, #-8]', 'mov x0, x22', 'bl 0x11000']
    helpers = {pc: ['ret'] for pc in (0x11000, 0x12000, 0x13000, 0x14000, 0x15000, 0x16000)}
    helpers.update({0x17000: ['brk #0', 'nop'], 0x17100: ['nop', 'ret'],
        0x5000: prefix + ['bl 0x6000', 'b 0x14000'], 0x6000: ['ret']})
    read = ['ldur w1, [x0, #7]', 'add x1, x1, x28, lsl #32']
    spill = ['stur x1, [x29, #-16]']
    call = ['bl 0x6000']
    reload = ['ldur x3, [x29, #-16]']
    def case(name, middle, want=1, mode='fields', extra=None):
        g = run('captured-' + name, prefix + ['bl 0x5000', 'bl 0x12000'] + middle +
            ['mov x0, x22', 'b 0x14000'], helpers | (extra or {}), async_contracts=True,
            completions='valid', future_bindings='valid', saved_refs=mode)
        assert sum(len(c['reloads']) for c in g['captured_field_contexts']) == want, (name, g['captured_field_contexts'])
        return g
    g = case('tagged-local', read + spill + call + reload)
    case('tagged-gap', read + spill + call + reload, mode='fields-gap')
    case('copied-register', read + ['mov x4, x1', 'stur x4, [x29, #-16]'] + call + reload)
    case('pair-store', read + ['stp x1, x22, [x29, #-16]'] + call + reload, 0) # reserved async slot overwritten
    case('pair-owned-locals', read + ['stp x1, x22, [x29, #-32]'] + call + ['ldur x3, [x29, #-32]'])
    case('narrow-spill', read + ['stur w1, [x29, #-16]'] + call + reload, 0)
    case('byte-overwrite', read + spill + ['strb w2, [x29, #-15]'] + call + reload, 0)
    case('word-overwrite', read + spill + ['stur w2, [x29, #-12]'] + call + reload, 0)
    case('simd-overwrite', read + spill + ['stur q0, [x29, #-16]'] + call + reload, 0)
    case('post-call-overwrite', read + spill + call + ['stur x2, [x29, #-16]'] + reload, 0)
    case('unknown-call', read + spill + ['bl 0x4000'] + reload, 0)
    case('indirect-call', read + spill + ['blr x4'] + reload, 0)
    case('missing-map', read + spill + call + reload, 0, 'fields-missing-map')
    case('unboxed-map', read + spill + call + reload, 0, 'fields-nonpointer')
    case('no-reconstruction', [read[0]] + spill + call + reload, 0)
    case('frame-escape', ['stur x29, [x0, #11]'] + read + spill + call + reload, 0)
    case('branch-boundary', read + spill + ['b 0x1030', 'nop'] + call + reload, 0)
    case('alternate-entry', read + spill + call + reload, 0, extra={0x9000: ['b 0x1030']})
    case('second-call', read + spill + call + call + reload, 0)
    case('heap-field-mutation', read + spill + ['stur w2, [x0, #7]'] + call + reload)
    case('multiple-reloads', read + spill + call + reload + ['ldur x4, [x29, #-16]'], 2)
    c = next(c for c in g['captured_field_contexts'] if c['reloads'])
    r = c['reloads'][0]
    assert 'captured Dart value only' in render(query(g, r['site']))
    text = '// ' + note(g, c, r) + f"\n// {r['site']:#x}: ldur x3, [x29, #-16]\n"
    assert sum(check_stream(g, io.StringIO(text)).values()) == 1
    for defect in ('scope', 'duplicate', 'work', 'frame', 'seed'):
        bad = copy.deepcopy(g)
        row = next(c for c in bad['captured_field_contexts'] if c['reloads'])
        if defect == 'scope':row['scope'] = 'ordinary_return'
        elif defect == 'duplicate':row['reloads'] *= 2
        elif defect == 'work':bad['captured_field_work']['steps'] += 1
        elif defect == 'frame':bad['saved_reference_frames'][0]['status'] = 'frame_address_escapes'
        else:row['access'] = 99
        try:validate_structure(bad)
        except (AssertionError, IndexError, KeyError):pass
        else:raise AssertionError('Forged captured value accepted: ' + defect)
    for defect in ('missing', 'duplicate', 'scope', 'slot'):
        bad = '' if defect == 'missing' else text.replace('// ' + note(g, c, r), '// ' + note(g, c, r) + '\n// ' + note(g, c, r)) if defect == 'duplicate' else text.replace('conditional:', 'unconditional:') if defect == 'scope' else text.replace('FP-16', 'FP-24')
        if defect == 'missing':bad = f"// {r['site']:#x}: ldur x3, [x29, #-16]\n"
        try:check_stream(g, io.StringIO(bad))
        except AssertionError:pass
        else:raise AssertionError('Forged captured value comment accepted: ' + defect)
