"""Authored container handoffs with physical callee-entry read contracts."""
import copy
import io
from callee_entry_reads import validate_structure, check_stream, note
from query_container_consumers import query, render


def run_cases(run):
    frame = ['stp x29, x30, [x15, #-16]!', 'mov x29, x15', 'sub x15, x15, #0x100']
    prefix = frame + ['stur x22, [x29, #-8]', 'mov x0, x22', 'bl 0x11000']
    helpers = {pc: ['ret'] for pc in (0x11000, 0x12000, 0x13000, 0x14000, 0x15000, 0x16000, 0x1c000, 0x7000)}
    helpers.update({0x17000: ['brk #0', 'nop'], 0x17100: ['nop', 'ret'],
        0x5000: prefix + ['bl 0x6000', 'b 0x14000'], 0x6000: ['ret']})
    caller = prefix + ['bl 0x5000', 'bl 0x12000', 'ldur w1, [x0, #7]',
        'add x1, x1, x28, lsl #32', 'stur x1, [x29, #-16]', 'mov x2, #6',
        'bl 0x6000', 'mov x2, x0', 'ldur x3, [x29, #-16]', 'stur w3, [x2, #15]']
    target = 0x1d000
    def case(name, body, want=1, outgoing=('str x2, [x15]',), extra=None):
        g = run('entry-' + name, caller + list(outgoing) + [f'bl {target:#x}', 'b 0x14000'],
            helpers | {target: body} | (extra or {}), async_contracts=True, completions='valid',
            future_bindings='valid', saved_refs='fields-fresh', call_inputs='valid')
        assert len(g['container_entry_read_links']) == want, (name, g['callee_entry_read_contracts'], g['fresh_content_contexts'])
        assert not any(c['inputs'] for c in g['fresh_content_contexts']), 'No descriptor-based source parameter role is claimed'
        return g
    g = case('base', frame + ['ldr x1, [x29, #16]', 'ret'])
    case('frameless', ['ldr x3, [x15]', 'ret'])
    case('stack-alias', ['mov x4, x15', 'sub x4, x4, #16', 'ldr x1, [x4, #16]', 'ret'])
    case('private-store', frame + ['str x2, [x15]', 'ldr x1, [x29, #16]', 'ret'])
    case('pair', ['ldp x1, x2, [x15]', 'ret'], 2, ('str x2, [x15]', 'str x2, [x15, #8]'))
    case('pair-base-alias', ['mov x3, x15', 'ldp x3, x2, [x3]', 'ret'], 2, ('str x2, [x15]', 'str x2, [x15, #8]'))
    case('later-write', ['ldr x1, [x15]', 'str x2, [x15]', 'ret'])
    case('later-call', ['ldr x1, [x15]', 'bl 0x7000', 'ret'])
    case('later-unknown', ['ldr x1, [x15]', 'fmov d0, x1', 'ret'])
    case('offset', ['ldr x3, [x15, #16]', 'ret'], 1, ('str x2, [x15, #16]',))
    case('wrong-word', ['ldr x3, [x15, #8]', 'ret'], 0)
    case('narrow', ['ldr w1, [x15]', 'ret'], 0)
    case('fpu', ['ldr d1, [x15]', 'ret'], 0)
    case('incoming-store', ['str x3, [x15]', 'ldr x1, [x15]', 'ret'], 0)
    case('unknown-store', ['str x3, [x4]', 'ldr x1, [x15]', 'ret'], 0)
    case('unowned-store', ['str x3, [x15, #-8]', 'ldr x1, [x15]', 'ret'], 0)
    case('ordinary-call', ['bl 0x7000', 'ldr x1, [x15]', 'ret'], 0)
    case('branch', [f'cbz x0, {target + 8:#x}', 'nop', 'ldr x1, [x15]', 'ret'], 0)
    case('frame-clobber', ['mov w4, w15', 'ldr x1, [x4]', 'ret'], 0)
    case('pair-frame-dest', ['ldp x1, x29, [x15]', 'ret'], 0)
    case('post-load', ['ldr x1, [x15], #8', 'ret'], 0)
    case('post-store', ['str x1, [x15], #8', 'ldr x2, [x15]', 'ret'], 0)
    case('no-outgoing', ['ldr x1, [x15]', 'ret'], 0, ())
    case('outgoing-overwritten', ['ldr x1, [x15]', 'ret'], 0, ('str x2, [x15]', 'str x22, [x15]'))
    case('prefix-bound', ['nop'] * 64 + ['ldr x1, [x15]', 'ret'], 0)
    guard = frame + ['ldr x16, [x26, #0x60]', 'cmp x15, x16', f'b.ls {target + 32:#x}',
        'ldr x1, [x29, #16]', 'ret', 'bl 0x3000', f'b {target + 24:#x}']
    case('guard', guard)
    for name, index, replacement in [('wrong-condition', 5, f'b.hi {target + 32:#x}'),
            ('wrong-limit', 3, 'ldr x16, [x26, #0x68]'), ('wrong-stub', 8, 'bl 0x7000'),
            ('wrong-rejoin', 9, f'b {target + 28:#x}'), ('slow-fallthrough', 7, 'nop')]:
        body = list(guard);body[index] = replacement;case(name, body, 0)
    l = g['container_entry_read_links'][0];site = g['fresh_content_contexts'][l['context']]['transfer']
    assert 'source parameter position/type and later element/field use unknown' in render(query(g, site))
    text = '// ' + note(g, l) + f'\n// {site:#x}: bl {target:#x}\n'
    assert sum(check_stream(g, io.StringIO(text)).values()) == 1
    for bad in (text + text, text.replace('SP+0x0', 'SP+0x8'), text.replace(f'// {site:#x}:', f'// {site+4:#x}:')):
        try:check_stream(g, io.StringIO(bad))
        except AssertionError:pass
        else:raise AssertionError('Forged entry-read annotation accepted')
    for key, value in [('scope', 'unconditional_source_parameter'), ('read', 99), ('context', -1), ('contract', -1)]:
        bad = copy.deepcopy(g);bad['container_entry_read_links'][0][key] = value
        try:validate_structure(bad)
        except (AssertionError, IndexError, KeyError):pass
        else:raise AssertionError('Forged entry-read structure accepted: ' + key)
