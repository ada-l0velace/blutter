"""Authored survival paths, with separately established container-input roles."""
import copy
import io
from fresh_content_uses import validate_structure, check_stream, note
from query_fresh_contents import query, render


def run_cases(run):
    prefix = ['stp x29, x30, [x15, #-16]!', 'mov x29, x15', 'sub x15, x15, #0x100',
        'stur x22, [x29, #-8]', 'mov x0, x22', 'bl 0x11000']
    helpers = {pc: ['ret'] for pc in (0x11000, 0x12000, 0x13000, 0x14000, 0x15000, 0x16000, 0x1c000, 0x7000, 0x18000)}
    helpers.update({0x17000: ['brk #0', 'nop'], 0x17100: ['nop', 'ret'],
        0x5000: prefix + ['bl 0x6000', 'b 0x14000'], 0x6000: ['ret']})
    read = ['ldur w1, [x0, #7]', 'add x1, x1, x28, lsl #32', 'stur x1, [x29, #-16]']
    array = ['mov x2, x0', 'ldur x3, [x29, #-16]', 'stur w3, [x2, #15]']
    start = 0x1000 + 4 * (len(prefix) + 2 + len(read) + 2 + len(array))
    def case(name, middle=(), want=1, tail=None, extra=None):
        code = prefix + ['bl 0x5000', 'bl 0x12000'] + read + ['mov x2, #6', 'bl 0x6000'] + array
        g = run('contents-' + name, code + list(middle) + (tail or ['mov x0, x2', 'b 0x14000']),
            helpers | (extra or {}), async_contracts=True, completions='valid', future_bindings='valid',
            saved_refs='fields-fresh', call_inputs='valid')
        assert sum(len(c['inputs']) for c in g['fresh_content_contexts']) == want, (name, g['fresh_content_contexts'])
        return g
    g = case('completion')
    case('copy', ['mov x4, x2', 'mov x2, x4'])
    case('other-element', ['stur w4, [x2, #19]'])
    case('overwritten', ['stur w4, [x2, #15]'], 0)
    case('partial-store', ['strb w4, [x2, #15]'], 0)
    case('unknown-alias-store', ['stur w4, [x5, #7]'], 0)
    case('escape', ['stur w2, [x5, #7]'], 0)
    case('narrow-copy', want=0, tail=['mov w0, w2', 'b 0x14000'])
    case('unknown-call', ['bl 0x4000'], 0)
    case('role-unproved', want=0, tail=['mov x0, x2', 'bl 0x4000', 'b 0x14000'])
    case('diamond', [f'cbz x3, {start + 8:#x}', 'stur w4, [x2, #19]'])
    case('one-path-overwrite', [f'cbz x3, {start + 8:#x}', 'stur w4, [x2, #15]'], 0)
    case('one-path-escape', [f'cbz x3, {start + 8:#x}', 'stur w2, [x5, #7]'], 0)
    case('one-path-lost', [f'cbz x3, {start + 8:#x}', 'mov x2, x4'], 0)
    case('different-first-transfers', [f'cbz x3, {start + 8:#x}', 'bl 0x4000'], 0)
    case('mint-diamond', [f'cbz x3, {start + 12:#x}', 'bl 0x7000', 'stur x3, [x0, #7]'])
    case('mint-unknown-store', [f'cbz x3, {start + 12:#x}', 'bl 0x7000', 'stur x3, [x5, #7]'], 0)
    case('external-entry', want=0, extra={0x9000: [f'b {start:#x}']})
    case('unvisited-incoming-branch', want=0, tail=['mov x0, x2', 'b 0x14000', f'b {start:#x}'])
    case('write-after-consumer', tail=['mov x0, x2', 'b 0x14000', 'stur w4, [x2, #15]'])
    case('loop', [f'cbz x3, {start:#x}'], 0)
    case('region-limit', ['nop'] * 128, 0)
    case('stack-input', ['str x2, [x15, #16]', 'str x22, [x15, #8]', 'str x22, [x15]',
        'ldr x4, [x27, #96]'], tail=['bl 0x18000', 'mov x0, x22', 'b 0x14000'])
    case('multiple-stack-inputs', ['str x2, [x15, #16]', 'str x2, [x15, #8]', 'str x22, [x15]',
        'ldr x4, [x27, #96]'], 2, tail=['bl 0x18000', 'mov x0, x22', 'b 0x14000'])
    case('stack-overwritten', ['str x2, [x15, #16]', 'str x22, [x15, #16]', 'str x22, [x15, #8]',
        'str x22, [x15]', 'ldr x4, [x27, #96]'], 0, tail=['bl 0x18000', 'b 0x14000'])
    case('stack-address-changed', ['str x2, [x15]', 'add x15, x15, #8'], 0)
    case('outgoing-stack-across-allocator', ['str x2, [x15]', 'bl 0x7000'], 0)
    c = next(c for c in g['fresh_content_contexts'] if c['inputs']);site = c['transfer']
    assert 'callee element/field use and value type unknown' in render(query(g, site))
    text = '// ' + note(g, c, c['inputs'][0]) + f'\n// {site:#x}: b 0x14000\n'
    assert sum(check_stream(g, io.StringIO(text)).values()) == 1
    for key, value in [('scope', 'permanent_contents'), ('initialization', 99), ('steps', 129), ('transfer', site + 4)]:
        bad = copy.deepcopy(g);bad['fresh_content_contexts'][0][key] = value
        try:validate_structure(bad)
        except (AssertionError, IndexError, KeyError):pass
        else:raise AssertionError('Forged content structure accepted: ' + key)
