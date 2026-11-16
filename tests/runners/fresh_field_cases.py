"""Authored first-write proofs, without source typing or persistent heap facts."""
import copy
import io
from fresh_field_initializations import validate_structure, check_stream, note
from query_fresh_fields import query, render


def run_cases(run):
    prefix = ['stp x29, x30, [x15, #-16]!', 'mov x29, x15', 'sub x15, x15, #0x100',
        'stur x22, [x29, #-8]', 'mov x0, x22', 'bl 0x11000']
    helpers = {pc: ['ret'] for pc in (0x11000, 0x12000, 0x13000, 0x14000, 0x15000, 0x16000, 0x1c000)}
    helpers.update({0x17000: ['brk #0', 'nop'], 0x17100: ['nop', 'ret'],
        0x5000: prefix + ['bl 0x6000', 'b 0x14000'], 0x6000: ['ret']})
    read = ['ldur w1, [x0, #7]', 'add x1, x1, x28, lsl #32', 'stur x1, [x29, #-16]']
    def case(name, after, want=1, target=0x6000, length='mov x2, #6', before=None, extra=None):
        g = run('fresh-' + name, prefix + ['bl 0x5000', 'bl 0x12000'] + read + (before or []) +
            [length, f'bl {target:#x}'] + after + ['mov x0, x22', 'b 0x14000'],
            helpers | (extra or {}), async_contracts=True, completions='valid', future_bindings='valid', saved_refs='fields-fresh')
        assert sum(bool(c['write']) for c in g['fresh_field_contexts']) == want, (name, g['fresh_field_contexts'])
        return g
    array = ['mov x2, x0', 'ldur x3, [x29, #-16]', 'stur w3, [x2, #15]']
    g = case('array-element', array)
    case('later-overwrite', array + ['stur w4, [x2, #15]'])
    case('later-escape', array + ['stur w2, [x4, #7]'])
    case('instance-field', ['ldur x3, [x29, #-16]', 'stur w3, [x0, #7]'], target=0x1c000)
    case('result-copies', ['mov x2, x0', 'mov x4, x2', 'ldur x3, [x29, #-16]', 'stur w3, [x4, #15]'])
    case('value-copies', array[:-1] + ['mov x4, x3', 'stur w4, [x2, #15]'])
    case('reload-overwrites-result', ['mov x2, x0', 'ldur x0, [x29, #-16]', 'stur w0, [x2, #15]'])
    case('result-lost', ['ldur x0, [x29, #-16]', 'stur w0, [x0, #15]'], 0)
    case('prior-same-element', array[:-1] + ['stur w4, [x2, #15]', array[-1]], 0)
    case('prior-other-element', array[:-1] + ['stur w4, [x2, #19]', array[-1]])
    case('narrow-store', array[:-1] + ['strb w3, [x2, #15]'], 0)
    case('wide-store', array[:-1] + ['stur x3, [x2, #15]'], 0)
    case('unboxed-field', ['ldur x3, [x29, #-16]', 'stur w3, [x0, #23]'], 0, target=0x1c000)
    case('type-arguments-field', ['ldur x3, [x29, #-16]', 'stur w3, [x0, #15]'], 0, target=0x1c000)
    case('header-field', ['ldur x3, [x29, #-16]', 'stur w3, [x0, #3]'], 0, target=0x1c000)
    case('empty-array', array, 0, length='mov x2, #0')
    case('odd-length', array, 0, length='mov x2, #7')
    case('unknown-length', array, 0, length='mov x2, x4')
    case('out-of-bounds', array[:-1] + ['stur w3, [x2, #27]'], 0)
    case('escaped-local', ['stur x0, [x29, #-32]'] + array, 0)
    case('escaped-heap', ['stur w0, [x4, #7]'] + array, 0)
    case('unproved-interior-alias', ['add x4, x0, #8'] + array, 0)
    case('narrow-result-copy', ['mov w2, w0'] + array[1:], 0)
    case('narrow-value-copy', array[:-1] + ['mov w3, w4', array[-1]], 0)
    case('unknown-alias-write', array[:-1] + ['stur w4, [x5, #7]', array[-1]], 0)
    case('call-boundary', array[:-1] + ['bl 0x4000', array[-1]], 0)
    case('branch-boundary', array[:-1] + ['b 0x1040', array[-1]], 0)
    case('alternate-write-entry', array, 0, extra={0x9000: ['b 0x103c']})
    c = next(c for c in g['fresh_field_contexts'] if c['write']);site = c['write']['site']
    assert 'later contents/type unknown' in render(query(g, site))
    text = '// ' + note(g, c) + f'\n// {site:#x}: stur w3, [x2, #15]\n'
    assert sum(check_stream(g, io.StringIO(text)).values()) == 1
    for defect in ('scope', 'missing', 'duplicate', 'work', 'source', 'class', 'site'):
        bad = copy.deepcopy(g);row = bad['fresh_field_contexts'][0]
        if defect == 'scope':row['scope'] = 'persistent_field_value'
        elif defect == 'missing':bad['fresh_field_contexts'] = []
        elif defect == 'duplicate':bad['fresh_field_contexts'] *= 2
        elif defect == 'work':bad['fresh_field_work']['steps'] += 1
        elif defect == 'source':row['capture'] = 99
        elif defect == 'class':row['class_id'] += 1
        else:row['write']['site'] = g['captured_field_contexts'][0]['reloads'][0]['site']
        try:validate_structure(bad)
        except (AssertionError, IndexError, KeyError):pass
        else:raise AssertionError('Forged fresh-write structure accepted: ' + defect)
