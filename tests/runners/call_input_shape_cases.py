"""Authored fixed-stack descriptor-use and control-flow fixtures."""
from call_input_shapes import input_records


def run_cases(run):
    helper = {0x18000: ['ret']}
    before = ['mov x1,#42', 'str x1,[x15]', 'ldr x2,[x27,#40]', 'str x2,[x15,#16]']
    call = ['ldr x4,[x27,#96]', 'bl 0x18000', 'ret']
    graph = run('supplied-input-multi', before + call, helper, call_inputs='normal')
    values = list(input_records(graph, include_unknown=True))
    assert [(v['index'], v['sp_offset'], v['kind']) for v in values] == [(0, 16, 'heap_class'), (1, 8, 'unknown'), (2, 0, 'word')]
    assert values[-1]['value'] == 42
    for mode in ('unsupported', 'mismatch'):
        graph = run('supplied-input-' + mode, before + call, helper, call_inputs=mode)
        assert not graph['call_input_shapes']
    for name, sequence in (
        ('truncated-load', ['ldr w4,[x27,#96]', 'bl 0x18000', 'ret']),
        ('wrong-register', ['ldr x3,[x27,#96]', 'bl 0x18000', 'ret']),
        ('clobber', ['ldr x4,[x27,#96]', 'mov x4,x0', 'bl 0x18000', 'ret']),
        ('wrong-pool', ['ldr x4,[x27,#104]', 'bl 0x18000', 'ret']),
        ('bypass-load', ['cbz x0,0x1018', 'ldr x4,[x27,#96]', 'bl 0x18000', 'ret']),
    ):
        graph = run('supplied-input-' + name, before + sequence, helper, call_inputs='normal')
        assert not graph['call_input_shapes']
    # A caller elsewhere in the inventory can also bypass this load.
    graph = run('supplied-input-cross-payload-bypass', before + call,
                helper | {0x19000: ['b 0x1014']}, call_inputs='normal')
    assert not graph['call_input_shapes']

    # Authored public-ABI prologue: its positive type-vector branch establishes
    # a descriptor protocol without a retained Function/signature model.
    prologue = ['stp x29,x30,[x15,#-16]!', 'mov x29,x15', 'sub x15,x15,#16',
                'ldur w0,[x4,#15]', 'cbnz w0,0x1801c', 'mov x0,x22', 'b 0x18028',
                'ldur w0,[x4,#23]', 'add x1,x29,w0,sxtw #2', 'ldr x1,[x1,#16]', 'ret']
    graph = run('descriptor-prologue-unnamed', before+call, {0x18000:prologue}, call_inputs='prologue')
    assert len(graph['call_input_shapes']) == 1 and not graph['call_input_models']
    assert graph['call_input_shapes'][0]['basis'] == 'callee_descriptor_prologue'
    for name, index, replacement in (
        ('frame', 1, 'mov x28,x15'), ('length-field', 3, 'ldur w0,[x4,#19]'),
        ('size-field', 7, 'ldur w0,[x4,#19]'), ('shift', 8, 'add x1,x29,w0,sxtw #3'),
        ('vector-slot', 9, 'ldr x1,[x1,#8]'), ('alias-kill', 3, 'ldur w4,[x4,#15]'),
        ('bypass-vector-load', 4, 'cbnz w0,0x18024')):
        wrong=list(prologue);wrong[index]=replacement
        graph=run('descriptor-prologue-reject-'+name,before+call,{0x18000:wrong},call_inputs='prologue')
        assert not graph['call_input_shapes']

    # Keep the branch/add internally consistent: these controls would otherwise
    # fail for an incidental register mismatch instead of the dangerous write.
    for name, replacements in (
        ('zero-length-register', {3:'ldur wzr,[x4,#15]',4:'cbnz wzr,0x1801c'}),
        ('frame-length-register', {3:'ldur w29,[x4,#15]',4:'cbnz w29,0x1801c'}),
        ('zero-size-register', {7:'ldur wzr,[x4,#23]',8:'add x1,x29,wzr,sxtw #2'})):
        wrong=list(prologue)
        for index,replacement in replacements.items():wrong[index]=replacement
        graph=run('descriptor-prologue-reject-'+name,before+call,{0x18000:wrong},call_inputs='prologue')
        assert not graph['call_input_shapes']

    optional = ['stp x29,x30,[x15,#-16]!', 'mov x29,x15', 'sub x15,x15,#16',
                'ldur w3,[x4,#19]', 'sub x3,x3,#2', 'add x1,x29,w3,sxtw #2', 'ldr x1,[x1,#16]', 'ret']
    graph = run('descriptor-optional-named', before+call, {0x18000:optional}, call_inputs='named')
    assert len(graph['call_input_shapes']) == 1 and graph['descriptor_prologues'][0]['parameter']
    assert graph['call_input_descriptors'][0]['named']==[dict(index=1,name='first'),dict(index=2,name='last')]
    for name,index,replacement in (
        ('wrong-count-field',3,'ldur w3,[x4,#27]'), ('clobbered-count',4,'mov x3,x0'),
        ('wrong-shift',5,'add x1,x29,w3,sxtw #3'), ('outside-packet',4,'sub x3,x3,#64'),
        ('bypass-prologue',2,'b 0x1800c')):
        bad=list(optional);bad[index]=replacement
        graph=run('descriptor-optional-reject-'+name,before+call,{0x18000:bad},call_inputs='named')
        assert not graph['call_input_shapes']
