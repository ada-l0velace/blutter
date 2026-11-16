"""Authored Future references and completion chains; no real program material."""

def run_cases(run):
    helpers={v:['ret'] for v in (0x11000,0x12000,0x13000,0x14000,0x15000,0x16000)}
    helpers.update({0x17000:['brk #0','nop'],0x17100:['nop','ret']})
    prefix=['stp x29, x30, [x15, #-16]!','mov x29, x15','sub x15, x15, #0x20',
            'stur x22, [x29, #-8]','mov x0, x22','bl 0x11000']
    leaf=prefix+['bl 0x6000','b 0x14000']
    caller=prefix+['bl 0x5000','bl 0x12000','b 0x14000']
    def one(name,body=caller,producer=leaf,extra=None,mode='valid',status='conditional_delivery',value=2):
        blocks=dict(helpers);blocks[0x5000]=producer;blocks.update(extra or {})
        graph=run('future-'+name,body,blocks,async_contracts=True,completions='valid',future_bindings=mode)
        rows=[v for v in graph['await_future_bindings'] if v['payload']==0x1000]
        if mode=='unsupported':
            assert not rows;return graph
        assert rows and rows[-1]['status']==status,(name,rows)
        assert rows[-1]['class_id']==(value if status=='conditional_delivery' else None),(name,rows[-1])
        return graph
    baseline=one('direct')
    disabled=one('scope-disabled',mode='unsupported')
    from async_future_bindings import FIELDS
    assert {k:v for k,v in baseline.items() if k not in FIELDS}=={k:v for k,v in disabled.items() if k not in FIELDS},'Async bindings changed old analysis facts'
    one('register-copy',prefix+['bl 0x5000','mov x8, x0','mov x0, x8','bl 0x12000','b 0x14000'])
    one('frame-spill',prefix+['bl 0x5000','stur x0, [x29, #-16]','ldur x0, [x29, #-16]','bl 0x12000','b 0x14000'])
    one('spill-overwrite',prefix+['bl 0x5000','stur x0, [x29, #-16]','stur x1, [x29, #-16]','ldur x0, [x29, #-16]','bl 0x12000','b 0x14000'],status='producer_origin_unproved')
    one('partial-spill',prefix+['bl 0x5000','stur w0, [x29, #-16]','ldur x0, [x29, #-16]','bl 0x12000','b 0x14000'],status='producer_origin_unproved')
    one('word-overwrite',prefix+['bl 0x5000','mov x0, #7','bl 0x12000','b 0x14000'],status='producer_origin_unproved')
    one('another-call',prefix+['bl 0x5000','bl 0x4000','bl 0x12000','b 0x14000'],status='no_completion_summary')
    one('indirect-producer',prefix+['blr x9','bl 0x12000','b 0x14000'],status='producer_origin_unproved')
    one('heap-field',prefix+['bl 0x5000','ldr x0, [x0, #7]','bl 0x12000','b 0x14000'],status='producer_origin_unproved')
    one('saved-across-await',prefix+['bl 0x5000','stur x0, [x29, #-16]','mov x0, x22','bl 0x12000',
        'ldur x0, [x29, #-16]','bl 0x12000','b 0x14000'],status='producer_origin_unproved')
    one('typed-await',prefix+['bl 0x5000','bl 0x13000','b 0x14000'],status='typed_await_delivery_unproved')
    one('no-initialization',producer=prefix[:-1]+['nop','bl 0x6000','b 0x14000'],status='completion_unproved')
    one('state-overwrite',producer=prefix+['stur x22, [x29, #-8]','bl 0x6000','b 0x14000'],status='suspend_state_overwritten')
    one('stack-state-overwrite',producer=prefix+['str x22, [x15, #24]','bl 0x6000','b 0x14000'],status='unproved_stack_write')
    one('partial-state-overwrite',producer=prefix+['sturb w1, [x29, #-8]','bl 0x6000','b 0x14000'],status='suspend_state_overwritten')
    one('frame-alias',producer=prefix+['mov x1, x29','bl 0x6000','b 0x14000'],status='frame_address_escapes')
    one('atomic-frame-store',producer=prefix+['stlr x0, [x15]','bl 0x6000','b 0x14000'],status='unsupported_frame_memory')
    one('missing-frame-save',producer=['nop']+leaf[1:],status='unproved_frame_anchor')
    one('alternate-entry',prefix+['bl 0x5018','bl 0x12000','b 0x14000'],status='uninitialized_suspend_state')
    bypass=prefix.copy();bypass[4]='cbz x1, 0x5018'
    one('bypass-init',producer=bypass+['bl 0x6000','b 0x14000'],status='initialization_bypassed')
    one('repeated-init',producer=prefix+['bl 0x11000','bl 0x6000','b 0x14000'],status='ambiguous_initialization')
    one('null',producer=prefix+['mov x0, x22','b 0x14000'],value=1)
    one('generic-null',producer=prefix+['mov x0, x22','b 0x15000'],value=1)
    one('generic-heap-unproved',producer=prefix+['bl 0x6000','b 0x15000'],status='completion_value_unproved')
    one('forward',producer=prefix+['bl 0x18000','b 0x15000'],extra={0x18000:leaf})
    one('opaque-forward',producer=prefix+['bl 0x4000','b 0x15000'],status='completion_value_unproved')
    one('cycle',producer=prefix+['bl 0x5000','b 0x15000'],status='completion_value_unproved')
    one('two-forwards',producer=prefix+['bl 0x18000','b 0x15000'],extra={0x18000:prefix+['bl 0x19000','b 0x15000'],0x19000:leaf})
    # One direct class and one forwarded, different class cannot agree.
    conflict=prefix+['cbz x1, 0x5024','bl 0x7000','b 0x14000','bl 0x18000','b 0x15000']
    one('forward-conflict',producer=conflict,extra={0x18000:leaf},status='conflicting_completion_values')
    deep={0x18000+n*0x100:prefix+([f'bl {0x18000+(n+1)*0x100:#x}','b 0x15000'] if n<7 else ['bl 0x6000','b 0x14000']) for n in range(8)}
    one('chain-bound',producer=prefix+['bl 0x18000','b 0x15000'],extra=deep,status='completion_value_unproved')
    one('handler-bypass',['bl 0x5000','bl 0x12000','ret'],mode='handler',status='producer_origin_unproved')
    one('external-entry',extra={0x30000:['b 0x101c']},status='producer_origin_unproved')
    one('dispatch-entry',prefix+['bl 0x5000','bl 0x12000','b 0x17000'],mode='dispatch-entry',status='producer_origin_unproved')
    one('completion-dispatch-entry',mode='dispatch-entry',status='producer_origin_unproved')
    one('missing-metadata',mode='missing',status='missing_caller_metadata')
    one('unsupported-abi',mode='unsupported')
    one('no-continuation',prefix+['bl 0x5000','bl 0x12000'],status='no_successful_continuation')
    argprefix=prefix[:4]+['add x0, x29, w3, sxtw #2','ldr x0, [x0, #8]']+prefix[4:]
    one('consumed-argument-address',producer=argprefix+['bl 0x6000','b 0x14000'])
    one('unconsumed-argument-address',producer=prefix[:4]+['add x0, x29, w3, sxtw #2','ldr x1, [x0, #8]']+prefix[4:]+['bl 0x6000','b 0x14000'],status='frame_address_escapes')
    one('separated-argument-address',producer=prefix[:4]+['add x0, x29, w3, sxtw #2','nop','ldr x0, [x0, #8]']+prefix[4:]+['bl 0x6000','b 0x14000'],status='frame_address_escapes')
    one('argument-address-after-init',producer=prefix+['add x0, x29, w3, sxtw #2','ldr x0, [x0, #8]','bl 0x6000','b 0x14000'],status='frame_address_escapes')
    one('stack-depth-merge',producer=prefix+['cbz x1, 0x5020','sub x15, x15, #16','stp x0, x1, [x15, #-16]!','bl 0x6000','b 0x14000'])
    one('stack-depth-unsafe',producer=prefix+['cbz x1, 0x5020','sub x15, x15, #16','str x1, [x15, #24]','bl 0x6000','b 0x14000'],status='unproved_stack_write')
    trap=one('recorded-trap',producer=prefix+['cbz x1, 0x5024','bl 0x6000','b 0x14000','brk #0','b 0x501c'])
    assert next(p for p in trap['future_producers'] if p['entry']==0x5000)['traps']==[0x5024]
    one('frame-control-overwrite',producer=prefix+['str x0, [x29]','bl 0x6000','b 0x14000'],status='frame_control_overwritten')
    one('missing-slot-clear',producer=prefix[:3]+['nop']+prefix[4:]+['bl 0x6000','b 0x14000'],status='uninitialized_suspend_state')
    one('frame-control-before-init',producer=prefix[:4]+['str x0, [x29]']+prefix[4:]+['bl 0x6000','b 0x14000'],status='frame_control_overwritten')
    one('uncertain-slot-before-init',producer=prefix[:4]+['cbz x1, 0x5018','sub x15, x15, #16','str x1, [x15, #24]']+prefix[4:]+['bl 0x6000','b 0x14000'],status='uninitialized_suspend_state')
    one('allocated-ldtr',producer=prefix+['ldtr x8, [x8]','bl 0x6000','b 0x14000'])
    one('ldtr-frame-clobber',producer=prefix+['ldtr x29, [x29]','bl 0x6000','b 0x14000'],status='frame_register_modified')
