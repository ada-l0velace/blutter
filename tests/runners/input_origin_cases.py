"""Authored producer/copy/spill, callback and field provenance controls."""


def run_cases(run):
    suffix=['str x0,[x15]', 'ldr x4,[x27,#96]', 'bl 0x18000', 'ret']
    helper={0x18000:['ret']}
    def observed(name,prefix,extra=None,**options):
        g=run('input-origin-'+name,prefix+suffix,helper|(extra or {}),call_inputs='normal',**options)
        return next(v for v in g['call_input_origins'] if v['role']=='supplied_input' and v['index']==2),g
    row,_=observed('literal-copy',['mov x2,#42','mov x0,x2'])
    assert row['chain'][0]['source']['bits']==42
    row,_=observed('zero-register',['mov x0,xzr'])
    assert row['chain'][0]['source']['kind']=='literal' and row['chain'][0]['source']['bits']==0
    row,_=observed('wide-negative',['movn x0,#123,lsl #48'])
    assert row['chain'][0]['source']['bits']==(~(123<<48))&((1<<64)-1)
    row,_=observed('frame-spill',['mov x1,#7','stur x1,[x29,#-8]','ldur x0,[x29,#-8]'])
    assert row['chain'][0]['source']['kind']=='literal' and row['chain'][0]['source']['bits']==7
    row,_=observed('ambiguous-spill',['mov x1,#7','stur x1,[x29,#-8]','str x2,[x3]','ldur x0,[x29,#-8]'])
    assert row['chain'][0]['source']['kind']=='load' # no claim about saved contents
    row,_=observed('partial-spill',['mov x1,#7','stur w1,[x29,#-8]','ldur x0,[x29,#-8]'])
    assert row['chain'][0]['source']['kind']=='load'
    row,_=observed('branch-barrier',['mov x0,#7','cbz x1,0x1010','nop','nop'])
    assert row['chain'][0]['source'] is None
    row,_=observed('call-result',['bl 0x19000'],{0x19000:['ret']})
    assert row['chain'][0]['source']['kind']=='post_call_x0'
    row,_=observed('field-base',['ldur x0,[x1,#7]'])
    assert row['chain'][0]['source']['load']['displacement']==7 and row['chain'][1]['source']['kind']=='entry_register'
    row,_=observed('compressed-field',['ldur w0,[x1,#7]','add x0,x0,x28,lsl #32'])
    assert row['chain'][0]['source']['kind']=='load_compressed'
    row,_=observed('compressed-computation',['mov x0,#7','add x0,x0,x28,lsl #32'])
    assert row['chain'][0]['source'] is None
    for layout,context in (('old',2),('new',3)):
        row,g=observed('closure-'+layout,['ldr x1,[x27,#40]',f'mov x{context},x22','bl 0x12000'],
                       {0x11000:['nop','ret'],0x12000:['nop','ret']},stub_inputs=layout)
        assert row['chain'][0]['source']['kind']=='post_call_x0'
        assert row['chain'][1]['relation']=='closure_function' and row['chain'][1]['pool_index']==3
        assert g['input_object_catalog']==[dict(pool_index=3,kind='function',text='authored_callback',entry=0x19000)]
    row,_=observed('unmatched-closure',['ldr x1,[x27,#40]','bl 0x12000'],{0x12000:['ret']})
    assert len(row['chain'])==1
    row,_=observed('deep-fields',['ldur x1,[x2,#7]','ldur x0,[x1,#15]'])
    assert len(row['chain'])==3 and row['chain'][-1]['source']['kind']=='entry_register'

    g=run('input-origin-pair-push',['mov x0,#7','mov x1,#9','stp x0,x1,[x15,#-16]!',
          'ldr x4,[x27,#96]','bl 0x18000','ret'],helper,call_inputs='normal')
    mapped={v['index']:v['chain'][0]['source'] for v in g['call_input_origins']}
    assert mapped[1]['bits']==9 and mapped[2]['bits']==7

    for layout,context in (('old',2),('new',3)):
        g=run('input-origin-stub-without-ordinary-policy-'+layout,
              ['ldr x1,[x27,#40]',f'mov x{context},x22','bl 0x12000','ret'],
              {0x11000:['ret'],0x12000:['ret']},stub_inputs=layout,call_inputs='unsupported')
        assert not g['call_input_abi']['supported'] and not g['call_input_shapes']
        assert any(o['role']=='closure_function' for o in g['call_input_origins'])
        assert all(o['role']!='supplied_input' for o in g['call_input_origins'])
