"""Authored saved-reference joins with optional and alternative suspensions."""
import copy
import io
from joined_async_references import validate_structure, check_stream, note
from query_joined_references import query, render
from field_branch_uses import check_stream as check_branch_stream, expected_notes


def run_cases(run):
    prefix = ['stp x29, x30, [x15, #-16]!', 'mov x29, x15', 'sub x15, x15, #0x100',
        'stur x22, [x29, #-8]', 'mov x0, x22', 'bl 0x11000']
    helpers = {pc: ['ret'] for pc in (0x11000,0x12000,0x13000,0x14000,0x15000,0x16000)}
    helpers.update({0x17000: ['brk #0','nop'],0x17100: ['nop','ret'],0x5000: prefix+['bl 0x6000','b 0x14000']})
    start = 0x1000 + 4 * (len(prefix) + 2)
    optional = ['stur x0, [x29, #-16]',f'cbz x1, {start+16:#x}','mov x0, x22','bl 0x12000','ldur x2, [x29, #-16]']
    def case(name, body=None, want=1, mode='valid', extra=None, after=()):
        g = run('joined-'+name, prefix+['bl 0x5000','bl 0x12000']+(body or optional)+['mov x0, x22','b 0x14000']+list(after),
            helpers | (extra or {}),async_contracts=True,completions='valid',future_bindings='valid',saved_refs=mode)
        observed = [o for c in g['joined_reference_contexts'] if c['payload']==0x1000 for o in c['observations']]
        assert len(observed)==want,(name,g['joined_reference_contexts'])
        return g
    g = case('optional')
    case('typed-await',optional[:3]+['bl 0x13000']+optional[4:])
    case('missing-map',want=0,mode='missing-map')
    case('unboxed',want=0,mode='nonpointer')
    case('unsupported',want=0,mode='unsupported')
    case('ordinary-spill',['stur x0, [x29, #-16]','ldur x2, [x29, #-16]'],0)
    case('common-suspension',['stur x0, [x29, #-16]',f'cbz x1, {start+12:#x}','nop','mov x0, x22','bl 0x12000','ldur x2, [x29, #-16]'],0)
    case('overwrite',[optional[0],optional[1],'stur x1, [x29, #-16]',optional[3],optional[4]],0)
    case('partial-overwrite',[optional[0],optional[1],'stur w1, [x29, #-12]',optional[3],optional[4]],0)
    case('narrow-save',['stur w0, [x29, #-16]']+optional[1:],0)
    case('ordinary-call',[optional[0],f'cbz x1, {start+16:#x}','bl 0x4000','bl 0x12000',optional[4]])
    case('external-entry',want=0,extra={0x9000:[f'b {start+16:#x}']})
    case('frame-escape',[optional[0],optional[1],'mov x1, x29',optional[3],optional[4]],0)
    case('different-definitions',[optional[0],f'cbz x1, {start+24:#x}','ldur x0, [x29, #-16]',optional[0],optional[2],optional[3],optional[4]],0)
    case('two-suspensions',[optional[0],f'cbz x1, {start+20:#x}',optional[2],optional[3],f'b {start+28:#x}',optional[2],optional[3],optional[4]])
    many=[optional[0]]
    for _ in range(9):
        pc=start+len(many)*4;many += [f'cbz x1, {pc+12:#x}',optional[2],optional[3]]
    case('history-bound',many+[optional[4]],0)
    case('later-mandatory',many+[optional[2],optional[3],optional[4]],0)
    c = next(c for c in g['joined_reference_contexts'] if c['observations']);o=c['observations'][0]
    assert o['last_suspensions']==[None,start+12]
    text='// '+note(c,o)+f"\n// {o['site']:#x}: ldur x2, [fp, #-16]\n"
    assert sum(check_stream(g,io.StringIO(text)).values())==1
    assert 'no additional await' in render(query(g,o['site']))
    for bad in [text+text,text.replace('reference only','field contents preserved'),text.replace(f"// {o['site']:#x}:",f"// {o['site']+4:#x}:")]:
        try:check_stream(g,io.StringIO(bad))
        except AssertionError:pass
        else:raise AssertionError('Forged joined-reference comment accepted')
    for key,value in [('scope','unconditional'),('class_id',99),('steps',200001)]:
        bad=copy.deepcopy(g);next(c for c in bad['joined_reference_contexts'] if c['observations'])[key]=value
        try:validate_structure(bad)
        except (AssertionError,KeyError):pass
        else:raise AssertionError('Forged joined-reference structure accepted: '+key)


    # The skip edge enters at the reload. An edge into any following instruction
    # can skip a necessary definition and must block the field comment.
    load = 'ldur w3, [x2, #7]'
    expand = 'add x3, x3, x28, lsl #32'
    branch_site = start + 28
    taken = branch_site + 8
    tbnz = f'tbnz w3, #4, {taken:#x}'

    def field_case(name, instructions, want=False, extra=None, mode='fields'):
        graph = case('field-' + name, optional + instructions, mode=mode, extra=extra)
        assert len(graph['field_branch_uses']) == int(want)
        return graph

    nonzero = field_case('tbnz', [load, expand, tbnz], want=True)
    proof = nonzero['field_branch_uses'][0]
    assert proof['site'] == branch_site and proof['offset'] == 8 and proof['bit'] == 4
    assert (proof['set_target'], proof['clear_target']) == (taken, branch_site + 4)
    zero = field_case('tbz', [load, expand, f'tbz w3, #31, {taken:#x}'], want=True)
    proof = zero['field_branch_uses'][0]
    assert proof['bit'] == 31 and (proof['set_target'], proof['clear_target']) == (branch_site + 4, taken)
    field_case('different-base', ['ldur w3, [x1, #7]', expand, tbnz])
    field_case('wrong-width', ['ldur x3, [x2, #7]', expand, tbnz])
    for name, displacement in [('header', 3), ('excluded', 15), ('unboxed', 23), ('outside', 31)]:
        field_case(name, [f'ldur w3, [x2, #{displacement}]', expand, tbnz])
    field_case('wrong-heap-register', [load, expand.replace('x28', 'x27'), tbnz])
    field_case('wrong-shift', [load, expand.replace('#32', '#31'), tbnz])
    field_case('wrong-register', [load, expand, tbnz.replace('w3', 'w4')])
    field_case('high-bit', [load, expand, tbnz.replace('w3, #4', 'x3, #36')])
    field_case('clobber', [load, 'mov w3, #16', tbnz])
    field_case('no-layout', [load, expand, tbnz], mode='valid')
    for offset in (0, 4, 8):
        local_entry = case(f'field-local-entry-{offset}', optional + [load, expand, tbnz],
                           mode='fields', after=[f'b {branch_site - 8 + offset:#x}'])
        assert local_entry['field_branch_work']['candidates'] == 1
        assert not local_entry['field_branch_uses']

    expected = expected_notes(nonzero)
    (_, comment), = expected
    exact = f'// {comment}\n// {branch_site:#x}: tbnz w3, #4, {taken:#x}\n'
    assert check_branch_stream(io.StringIO(exact), expected) == expected
    for forged in (exact.replace('bit 4', 'bit 5'), exact.replace(f'{branch_site:#x}', f'{branch_site+4:#x}')):
        try:
            check_branch_stream(io.StringIO(forged), expected)
        except AssertionError:
            pass
        else:
            raise AssertionError('Forged field bit test comment accepted')

    from field_decision_cases import run_cases as run_decisions
    run_decisions(run)
