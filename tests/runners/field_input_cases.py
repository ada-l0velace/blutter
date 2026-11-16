"""Authored field words supplied to established SDK/descriptor input locations."""
import copy
import io
from field_input_origins import check_field_inputs, check_stream, note
from query_field_inputs import query, render


def run_cases(run):
    prefix = ['stp x29, x30, [x15, #-16]!', 'mov x29, x15', 'sub x15, x15, #0x100',
              'stur x22, [x29, #-8]', 'mov x0, x22', 'bl 0x11000']
    helpers = {pc: ['ret'] for pc in (0x11000, 0x12000, 0x13000, 0x14000, 0x15000, 0x16000,
                                    0x18000, 0x19000, 0x1a000, 0x1b000)}
    helpers.update({0x17000: ['brk #0', 'nop'], 0x17100: ['nop', 'ret'],
                    0x5000: prefix + ['bl 0x6000', 'b 0x14000']})
    read = ['ldur w1, [x0, #7]', 'add x1, x1, x28, lsl #32']
    def case(name, middle, want=1, mode='field-inputs'):
        g = run('field-input-' + name, prefix + ['bl 0x5000', 'bl 0x12000'] + middle +
                ['mov x0, x22', 'b 0x14000'], helpers, async_contracts=True,
                completions='valid', future_bindings='valid', saved_refs='fields',
                call_inputs='valid', stub_inputs=mode)
        assert len(g['async_field_input_links']) == want, (name, g['async_field_input_links'])
        return g
    g = case('sdk-role', read + ['bl 0x1a000'])
    case('copies', read + ['mov x4, x1', 'mov x1, x4', 'bl 0x1a000'])
    case('full-spill', read + ['stur x1, [x29, #-16]', 'mov x1, x22', 'ldur x1, [x29, #-16]', 'bl 0x1a000'])
    case('narrow-spill', read + ['stur w1, [x29, #-16]', 'mov x1, x22', 'ldur x1, [x29, #-16]', 'bl 0x1a000'], 0)
    case('overwritten', read + ['mov x1, x22', 'bl 0x1a000'], 0)
    case('unknown-call', read + ['bl 0x4000', 'bl 0x1a000'], 0)
    case('role-unproved', read + ['bl 0x4000'], 0)
    case('unreconstructed', ['ldur w1, [x0, #7]', 'bl 0x1a000'], 0)
    case('nested-base', read + ['ldur w1, [x1, #7]', 'add x1, x1, x28, lsl #32', 'bl 0x1a000'], 0)
    case('later-field-write', read + ['stur w2, [x0, #7]', 'bl 0x1a000'])
    case('supplied-stack', read + ['str x1, [x15, #16]', 'str x22, [x15, #8]', 'str x22, [x15]',
                                  'ldr x4, [x27, #96]', 'bl 0x18000'])
    case('supplied-multiple', read + ['str x1, [x15, #16]', 'str x1, [x15, #8]', 'str x22, [x15]',
                                     'ldr x4, [x27, #96]', 'bl 0x18000'], 2)
    case('old-closure-context', ['ldur w2, [x0, #7]', 'add x2, x2, x28, lsl #32',
         'ldr x1, [x27, #40]', 'bl 0x1b000'], mode='field-inputs-old')
    case('new-closure-context', ['ldur w3, [x0, #7]', 'add x3, x3, x28, lsl #32',
         'ldr x1, [x27, #40]', 'mov x2, #64', 'bl 0x1b000'])
    case('async-completion', ['ldur w0, [x0, #7]', 'add x0, x0, x28, lsl #32', 'b 0x14000'])
    link = g['async_field_input_links'][0]
    site = g['call_input_origins'][link['input_origin']]['site']
    assert 'field value/type unknown' in render(query(g, site))
    text = '// ' + note(g, link) + f'\n// {site:#x}: bl 0x1a000\n'
    assert sum(check_stream(g, io.StringIO(text)).values()) == 1
    for key, value in [('scope', 'unconditional'), ('context', 99), ('access', 99), ('input_origin', 99)]:
        bad = copy.deepcopy(g)
        bad['async_field_input_links'][0][key] = value
        try:
            check_field_inputs(bad)
        except (AssertionError, IndexError, KeyError):
            pass
        else:
            raise AssertionError('Forged field input link accepted: ' + key)
