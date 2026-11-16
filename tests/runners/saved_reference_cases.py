"""Authored frame locals and suspend/resume boundaries; no program extracts."""

def run_cases(run):
    prefix=['stp x29, x30, [x15, #-16]!', 'mov x29, x15', 'sub x15, x15, #0x100',
            'stur x22, [x29, #-8]', 'mov x0, x22', 'bl 0x11000']
    helpers={pc:['ret'] for pc in (0x11000,0x12000,0x13000,0x14000,0x15000,0x16000)}
    helpers.update({0x17000:['brk #0','nop'],0x17100:['nop','ret']})
    leaf=prefix+['bl 0x6000','b 0x14000']
    def case(name,middle=None,mode='valid',want=1,body=None):
        instructions=body or prefix+['bl 0x5000','bl 0x12000']+(middle or ['stur x0, [x29, #-16]', 'mov x0, x22', 'bl 0x12000', 'ldur x2, [x29, #-16]'])+['mov x0, x22','b 0x14000']
        g=run('saved-'+name,instructions,helpers|{0x5000:leaf},async_contracts=True,
              completions='valid',future_bindings='valid',saved_refs=mode)
        contexts=[c for c in g['saved_reference_contexts'] if c['payload']==0x1000 and c['class_id']==2]
        observed=[o for c in contexts for o in c['observations']]
        assert len(observed)==want,(name,contexts)
        for o in observed:
            assert o['register']==2 and o['slot']< -8 and o['store']<o['suspension']<o['site'],(name,o)
        return g
    case('direct')
    case('copy',['mov x4, x0','stur x4, [x29, #-16]','mov x0, x22','bl 0x12000','ldur x2, [x29, #-16]'])
    case('ordinary-call',['stur x0, [x29, #-16]','bl 0x4000','mov x0, x22','bl 0x12000','ldur x2, [x29, #-16]'])
    case('typed-intervening-await',['stur x0, [x29, #-16]','mov x0, x22','bl 0x13000','ldur x2, [x29, #-16]'])
    case('no-suspension',['stur x0, [x29, #-16]','ldur x2, [x29, #-16]'],want=0)
    case('overwritten',['stur x0, [x29, #-16]','stur x1, [x29, #-16]','mov x0, x22','bl 0x12000','ldur x2, [x29, #-16]'],want=0)
    case('partial-write',['stur x0, [x29, #-16]','stur w1, [x29, #-12]','mov x0, x22','bl 0x12000','ldur x2, [x29, #-16]'],want=0)
    case('narrow-store',['stur w0, [x29, #-16]','mov x0, x22','bl 0x12000','ldur x2, [x29, #-16]'],want=0)
    case('narrow-source',['mov w0, w0','stur x0, [x29, #-16]','mov x0, x22','bl 0x12000','ldur x2, [x29, #-16]'],want=0)
    case('missing-map',mode='missing-map',want=0)
    case('nonpointer-slot',mode='nonpointer',want=0)
    case('unsupported',mode='unsupported',want=0)
    case('frame-escape',['stur x0, [x29, #-16]','mov x1, x29','bl 0x12000','ldur x2, [x29, #-16]'],want=0)
    case('reserved-slot',['stur x0, [x29, #-8]','bl 0x12000','ldur x2, [x29, #-8]'],want=0)
    case('native-stack-escape',['stur x0, [x29, #-16]','mov x1, sp','bl 0x4000','mov x0, x22','bl 0x12000','ldur x2, [x29, #-16]'],want=0)
    case('entry-bypass',mode='entry',want=0)
    case('sp-store',['str x0, [x15, #240]','mov x0, x22','bl 0x12000','ldur x2, [x29, #-16]'])
    case('sp-overwrite',['stur x0, [x29, #-16]','str x1, [x15, #240]','mov x0, x22','bl 0x12000','ldur x2, [x29, #-16]'],want=0)
    case('pair-store',['stp x0, x1, [x29, #-24]','mov x0, x22','bl 0x12000','ldur x2, [x29, #-24]'])
    case('heap-write',['stur x0, [x29, #-16]','stur x1, [x0, #7]','mov x0, x22','bl 0x12000','ldur x2, [x29, #-16]'])
    case('post-index-clobber',['str x1, [x0], #8','stur x0, [x29, #-16]','mov x0, x22','bl 0x12000','ldur x2, [x29, #-16]'],want=0)
    # Both paths reach one common suspension. A write on one path kills agreement.
    case('branch-keeps',['stur x0, [x29, #-16]','cbz x1, 0x102c','nop','mov x0, x22','bl 0x12000','ldur x2, [x29, #-16]'])
    case('branch-overwrites',['stur x0, [x29, #-16]','cbz x1, 0x102c','stur x1, [x29, #-16]','mov x0, x22','bl 0x12000','ldur x2, [x29, #-16]'],want=0)
    case('second-save-needs-suspend',['stur x0, [x29, #-16]','mov x0, x22','bl 0x12000','ldur x2, [x29, #-16]','stur x2, [x29, #-24]','ldur x3, [x29, #-24]'])
