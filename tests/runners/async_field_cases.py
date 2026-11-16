"""Authored boxed-owner reads and writes, with explicit unknown field contents."""
import copy
import io
from async_field_accesses import check_fields, check_stream, note


def run_cases(run):
    prefix = ['stp x29, x30, [x15, #-16]!', 'mov x29, x15', 'sub x15, x15, #0x100',
              'stur x22, [x29, #-8]', 'mov x0, x22', 'bl 0x11000']
    helpers = {pc: ['ret'] for pc in (0x11000, 0x12000, 0x13000, 0x14000, 0x15000, 0x16000)}
    helpers.update({0x17000: ['brk #0', 'nop'], 0x17100: ['nop', 'ret'],
                    0x5000: prefix + ['bl 0x6000', 'b 0x14000']})
    def case(name, middle, want):
        g = run('fields-' + name, prefix + ['bl 0x5000', 'bl 0x12000'] + middle +
                ['mov x0, x22', 'b 0x14000'], helpers, async_contracts=True,
                completions='valid', future_bindings='valid', saved_refs='fields')
        observations = [a for c in g['async_field_contexts'] for a in c['accesses']]
        assert len(observations) == want, (name, observations)
        return g
    g = case('read-write', ['ldur w1, [x0, #7]', 'stur w2, [x0, #11]'], 2)
    case('copy', ['mov x3, x0', 'ldur w1, [x3, #7]'], 1)
    case('narrow-copy', ['mov w0, w0', 'ldur w1, [x0, #7]'], 0)
    case('overwritten-owner', ['ldur w0, [x0, #7]', 'ldur w1, [x0, #7]'], 1)
    case('type-arguments', ['ldur w1, [x0, #15]'], 0)
    case('unboxed-storage', ['ldur w1, [x0, #23]'], 0)
    case('header', ['ldur w1, [x0, #-1]'], 0)
    case('wide-read', ['ldur x1, [x0, #7]'], 0)
    case('call-boundary', ['bl 0x4000', 'ldur w1, [x0, #7]'], 0)
    case('saved-reference', ['stur x0, [x29, #-16]', 'mov x0, x22', 'bl 0x12000',
         'ldur x2, [x29, #-16]', 'ldur w1, [x2, #7]'], 1)
    context = next(c for c in g['async_field_contexts'] if c['accesses'])
    access = context['accesses'][0]
    layout = next(l for l in g['async_field_layouts'] if l['class_id'] == context['class_id'])
    text = note(context, access, layout)
    stream = '// ' + text + f"\n// {access['site']:#x}: ldur w1, [x0, #7]\n"
    assert sum(check_stream(g, io.StringIO(stream)).values()) == 1
    for forged in [stream.replace('conditional:', 'unconditional:'), stream.replace('field value unknown', 'value bool'),
                   stream + stream, stream.replace(f"{access['site']:#x}:", f"{access['site'] + 4:#x}:")]:
        try:
            check_stream(g, io.StringIO(forged))
        except AssertionError:
            pass
        else:
            raise AssertionError('Forged field annotation accepted')
    bad = copy.deepcopy(g)
    bad['async_field_contexts'][0]['scope'] = 'unconditional'
    try:
        check_stream(bad, io.StringIO(stream))
    except AssertionError:
        pass
    else:
        raise AssertionError('Lost field scope accepted')
