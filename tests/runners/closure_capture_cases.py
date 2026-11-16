"""Authored closure argument, capture read, local save and object initialization."""
import copy
from closure_capture_transfers import expected_notes


def run_cases(run):
    body = ['stp x29, x30, [x15, #-16]!', 'mov x29, x15', 'sub x15, x15, #8',
            'ldr x0, [x29, #24]', 'ldur w1, [x0, #35]', 'add x1, x1, x28, lsl #32',
            'ldur w0, [x1, #15]', 'add x0, x0, x28, lsl #32',
            'stur x0, [x29, #-8]', 'bl 0x8000', 'ldur x1, [x29, #-8]',
            'stur w1, [x0, #11]', 'mov x15, x29', 'ldp x29, x30, [x15], #16', 'ret']
    caller = ['ldr x1, [x27, #40]', 'ldr x3, [x27, #56]', 'mov x2, #128', 'bl 0x12000']
    def case(name, changes=None, mode='valid', want=0, after=(), repeat=False):
        code=body.copy()
        for index,word in (changes or {}).items():code[index]=word
        invocation=caller.copy()
        if mode=='legacy':invocation=['ldr x1, [x27, #40]', 'ldr x2, [x27, #56]', 'nop', 'bl 0x12000']
        graph=run('closure-'+name,invocation*(2 if repeat else 1)+['ret'],
            {0x11000:['ret'],0x12000:['ret'],0x8000:['ret'],0x19000:code+list(after)},
            stub_inputs='old' if mode=='legacy' else 'new',closure_captures=mode)
        assert len(graph['closure_capture_transfers'])==want,(name,graph['closure_capture_work'],graph['closure_capture_transfers'])
        return graph
    graph=case('base',want=1)
    assert not graph['call_input_abi']['supported']
    assert not graph['call_input_shapes']
    assert any(o['role']=='closure_function' for o in graph['call_input_origins'])
    transfer,=graph['closure_capture_transfers']
    assert transfer['entry_sp_offset']==8 and transfer['value_read']==0x19018
    assert transfer['store']==0x1902c and transfer['destination_offset']==12
    assert sum(expected_notes(graph).values())==2
    repeated=case('repeated-entry',want=2,repeat=True)
    assert sum(expected_notes(repeated).values())==3
    case('legacy',{4:'ldur w1, [x0, #19]'},mode='legacy',want=1)
    case('discarded',mode='discarded',want=1)
    for mode in ('missing-model','missing-map','untagged','arity','missing-body','handler'):
        case(mode,mode=mode)
    for name,index,word in [
        ('wrong-closure-argument',3,'ldr x0, [x29, #16]'),
        ('wrong-capture-offset',4,'ldur w1, [x0, #31]'),
        ('wrong-heap-register',5,'add x1, x1, x27, lsl #32'),
        ('wrong-value-base',6,'ldur w0, [x0, #15]'),
        ('wrong-value-width',6,'ldur x0, [x1, #15]'),
        ('wrong-local',8,'stur x0, [x29, #-16]'),
        ('wrong-allocation',9,'bl 0x12000'),
        ('wrong-reload',10,'ldur x1, [x29, #-16]'),
        ('result-clobber',10,'ldur x0, [x29, #-8]'),
        ('wrong-destination-value',11,'stur w2, [x0, #11]'),
        ('wrong-destination-base',11,'stur w1, [x2, #11]'),
        ('unboxed-destination',11,'stur w1, [x0, #23]'),
        ('excluded-destination',11,'stur w1, [x0, #15]'),
    ]:
        case(name,{index:word})
    case('extra-entry',after=['b 0x19018'])
