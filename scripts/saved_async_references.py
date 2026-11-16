"""Validate saved reference claims from original instructions and typed GC maps.

The replay tracks physical reference copies and intersects definitions at joins.
It grants no stable heap-field contents or ordinary source return type.
"""
import collections
from async_future_bindings import _frame_proof

FIELDS=('saved_reference_abi','saved_reference_frames','saved_reference_stack_maps',
        'saved_reference_contexts','saved_reference_work')
LIMIT=2000000
SCOPE='conditional_saved_reference_only'


def replay(insns,seed,points,maps,entries,handlers,asyncs,exceptions,nonreturning,first_local,reserved,*,joined=False,local=None):
    import capstone as cs
    from capstone import arm64 as a
    by_pc={i.address:i for i in insns}
    zero=frozenset({0}) if joined else 0
    initial = ({}, {local['slot']:(local['store'],zero,local['slot'])}) if local else ({0:(0,zero,0)},{})
    states={seed:initial};queue=collections.deque([seed])
    def number(reg):
        n=insns[0].reg_name(reg)
        return 29 if n=='fp' else 30 if n=='lr' else int(n[1:]) if n and n[0] in 'xw' and n[1:].isdigit() else -1
    def width(reg):
        n=insns[0].reg_name(reg)
        return 16 if n.startswith('q') else 8 if n.startswith(('x','d')) or n in ('fp','lr') else 4 if n.startswith(('w','s')) else 0
    def target(i):return i.operands[-1].imm if i.operands and i.operands[-1].type==a.ARM64_OP_IMM else None
    def plain(i):return i.id==a.ARM64_INS_B and i.cc in (a.ARM64_CC_INVALID,a.ARM64_CC_AL)
    def trim(pc,state):
        regs,slots=map(dict,state)
        if pc not in points or pc in entries or pc in handlers:return {},{}
        return regs,{off:v for off,v in slots.items() if off>=points[pc][0]}
    def merge(old,new):
        out={}
        for k,v in old.items():
            if k in new and (v[0],v[2])==(new[k][0],new[k][2]):
                if joined:
                    histories=v[1] | new[k][1] if v[1] and new[k][1] else frozenset()
                    if len(histories)>8:histories=frozenset()
                else:histories=v[1] if v[1]==new[k][1] else 0
                out[k]=(v[0],histories,v[2])
        return out
    def push(pc,state):
        assert pc in by_pc,'Unproved control leaves the frame'
        if pc not in states:states[pc]=state;queue.append(pc)
        else:
            joined=tuple(merge(old,new) for old,new in zip(states[pc],state))
            if joined!=states[pc]:states[pc]=joined;queue.append(pc)
    stores=tuple(getattr(a,'ARM64_INS_'+n) for n in ('STR','STUR','STRB','STURB','STRH','STURH','STP'))
    loads=(a.ARM64_INS_LDR,a.ARM64_INS_LDUR,a.ARM64_INS_LDTR)
    visits=0
    while queue:
        pc=queue.popleft();visits+=1
        assert visits<=LIMIT,'Independent reference replay exceeded its bound'
        i=by_pc[pc];o=i.operands;regs,slots=trim(pc,states[pc]);dest=target(i);call=i.group(cs.CS_GRP_CALL);ex=exceptions.get(dest)
        if i.id==a.ARM64_INS_BRK or (call or plain(i)) and ex and (not ex['tail_only'] or plain(i)) or call and dest in nonreturning:continue
        op=asyncs.get(dest)
        if plain(i) and op in ('complete_value','complete_value_or_future'):continue
        if call:
            m=maps.get(pc)
            slots={off:(v[0],(frozenset({pc}) if joined else pc) if op in ('await','await_with_type_check') else v[1],off) for off,v in slots.items() if m and m['available'] and off in m['objects']}
            regs={}
        elif i.group(cs.CS_GRP_JUMP):
            push(dest,(regs.copy(),slots.copy()))
            if plain(i):continue
        elif i.id in stores:
            m=o[-1].mem;base=number(m.base)
            if base in (15,29):
                size=1 if i.id in (a.ARM64_INS_STRB,a.ARM64_INS_STURB) else 2 if i.id in (a.ARM64_INS_STRH,a.ARM64_INS_STURH) else width(o[0].reg)
                count=2 if i.id==a.ARM64_INS_STP else 1
                if m.index or i.writeback and base!=15 or base==15 and (pc not in points or not points[pc][1]):slots={}
                else:
                    offset=m.disp+(points[pc][0] if base==15 else 0)
                    slots={off:v for off,v in slots.items() if not offset<off+8 or not offset+size*count>off}
                    for n in range(count):
                        off=offset+n*size
                        if size==8 and off>=-4096 and off%8==0 and off<=first_local and off+8<=reserved and number(o[n].reg) in regs:slots[off]=(pc,zero,off)
            if i.writeback:regs.pop(base,None)
        elif i.id in loads and len(o)==2 and not i.writeback and o[0].type==a.ARM64_OP_REG and width(o[0].reg)==8 and 0<=number(o[0].reg)<15 and o[1].type==a.ARM64_OP_MEM and o[1].mem.base==a.ARM64_REG_X29 and not o[1].mem.index:
            reg=number(o[0].reg);regs.pop(reg,None)
            if o[1].mem.disp in slots:regs[reg]=slots[o[1].mem.disp]
        else:
            # Architectural write sets intentionally preserve more registers
            # than the native lowerer's opaque fallback. Claims must be a
            # subset of these independently derived reaching definitions.
            prior=dict(regs)
            written={number(r) for r in i.regs_write}
            written.update(number(v.reg) for v in o if v.type==a.ARM64_OP_REG and v.access&cs.CS_AC_WRITE)
            if i.writeback:written.update(number(v.mem.base) for v in o if v.type==a.ARM64_OP_MEM)
            for reg in written:regs.pop(reg,None)
            if i.id==a.ARM64_INS_MOV and len(o)==2 and o[0].type==o[1].type==a.ARM64_OP_REG and width(o[0].reg)==width(o[1].reg)==8 and number(o[0].reg)<15 and number(o[1].reg) in prior:regs[number(o[0].reg)]=prior[number(o[1].reg)]
        push(pc+4,(regs,slots))
    observations=[]
    for pc,state in sorted(states.items()):
        i=by_pc[pc];o=i.operands;_,slots=trim(pc,state)
        if i.id in loads and len(o)==2 and not i.writeback and o[0].type==a.ARM64_OP_REG and width(o[0].reg)==8 and 0<=number(o[0].reg)<15 and o[1].type==a.ARM64_OP_MEM and o[1].mem.base==a.ARM64_REG_X29 and not o[1].mem.index:
            if o[1].mem.disp in slots:
                store,suspend,off=slots[o[1].mem.disp]
                if local is not None:
                    observations.append(dict(site=pc,store=store,slot=off,register=number(o[0].reg)))
                elif joined:
                    if len(suspend)>1:observations.append(dict(site=pc,store=store,slot=off,register=number(o[0].reg),last_suspensions=[x or None for x in sorted(suspend)]))
                elif suspend:observations.append(dict(site=pc,store=store,suspension=suspend,slot=off,register=number(o[0].reg)))
    return observations,len(states)


def check_saved_references(graph,audit,read):
    if graph.get('format',0)<39:return 0
    import capstone as cs
    from check_snapshot_annotations import decode_payload
    abi=graph['saved_reference_abi'];frames=graph['saved_reference_frames'];contexts=graph['saved_reference_contexts'];maps=graph['saved_reference_stack_maps'];work=graph['saved_reference_work']
    assert type(abi['supported']) is bool
    assert work['limit']==LIMIT and work['steps']+work['remaining']==LIMIT and work['map_limit']==16384 and work['region_limit']==2048 and work['byte_limit']==8388608
    if not abi['supported']:
        assert abi==dict(supported=False,first_local_offset=0) and not frames and not contexts and not maps and work['steps']==work['bytes']==work['map_drops']==0
        return 0
    assert audit is not None and abi==audit['saved_reference_abi'],'Saved frame ABI differs from VM audit'
    first=abi['first_local_offset'];assert type(first) is int and -4096<=first<=-8 and first%8==0
    md=cs.Cs(cs.CS_ARCH_ARM64,cs.CS_MODE_LITTLE_ENDIAN);md.detail=True
    summaries={s['payload']:s for s in graph['completion_summaries']};bodies={s['payload']:s for s in graph['future_binding_bodies']}
    seeds={(b['payload'],b['site']):b for b in graph['await_future_bindings'] if b['status']=='conditional_delivery'}
    assert [(c['payload'],c['source_await']) for c in contexts]==sorted(seeds),'Missing or duplicate saved-reference context'
    assert [f['payload'] for f in frames]==sorted({p for p,_ in seeds})
    nodes={n['start']:n for n in graph['nodes']};await_payloads={b['payload'] for b in graph['async_boundaries'] if b['operation'] in ('await','await_with_type_check')}
    cached=set();byte_count=0
    for payload,n in sorted(nodes.items()):
        size=n['end']-payload
        if payload in await_payloads and n['decoded'] and size<=65536 and size<=8388608-byte_count:cached.add(payload);byte_count+=size
    assert work['bytes']==byte_count,'Saved-reference byte-cache accounting differs'
    typed={(m['payload'],m['site']):m for m in audit['saved_reference_stack_maps']}
    assert [m['site'] for m in maps]==sorted({m['site'] for m in maps}) and len(maps)<=16384
    assert type(work['map_drops']) is int and work['map_drops']>=0 and (len(maps)==16384 or work['map_drops']==0)
    for m in maps:assert m==typed.get((m['payload'],m['site'])),'Saved-reference GC map differs from typed audit'
    published_maps={m['site']:m for m in maps};entries=set(graph['receiver_metadata']['entries']);asyncs={a['entry']:a['operation'] for a in graph['async_contracts']};exceptions={e['entry']:e for e in graph['completion_exception_contracts']};nonreturning=dict(graph['receiver_metadata']['nonreturning_calls'])
    remaining=LIMIT;count=0
    for f in frames:
        payload=f['payload'];cs_group=[c for c in contexts if c['payload']==payload]
        if payload not in summaries:expected=dict(status='no_completion_summary',steps=0,points=[]);insns=[]
        elif payload not in cached:expected=dict(status='missing_caller_bytes',steps=0,points=[]);insns=[]
        else:
            insns=list(decode_payload(md,read(payload,nodes[payload]['end']-payload),payload))
            expected,remaining=_frame_proof(insns,payload,summaries[payload],bodies[payload],graph['future_binding_abi']['suspend_state_offset'],asyncs,exceptions,nonreturning,remaining,reference_entries=entries)
        assert all(f[k]==expected[k] for k in ('status','steps','points')),('Saved frame protocol mismatch',hex(payload),f['status'],expected['status'])
        for c in cs_group:
            seed=seeds[payload,c['source_await']]
            assert c['class_id']==seed['class_id'] and c['scope']==SCOPE and type(c['steps']) is int and 0<=c['steps']<=remaining
            if f['status']!='matched_async_frame':assert c['status']==f['status'] and c['steps']==0 and not c['observations'];continue
            if c['status']=='checked':
                observations,nodes_seen=replay(insns,seed['resume_site'],{p:(sp,exact) for p,sp,exact in f['points']},published_maps,entries,set(bodies[payload]['handlers']),asyncs,exceptions,nonreturning,first,graph['future_binding_abi']['suspend_state_offset'])
                assert nodes_seen<=2048 and c['steps']>=nodes_seen
                assert c['observations']==sorted(c['observations'],key=lambda o:o['site'])
                assert len({o['site'] for o in c['observations']})==len(c['observations'])
                for o in c['observations']:assert o in observations,('Unproved restored reference',hex(c['source_await']),o)
                count+=len(c['observations'])
            else:
                assert c['status'] in ('region_limit','step_limit','unsupported_control','unsupported_resume') and not c['observations']
                if c['status']=='step_limit':assert c['steps']==remaining
            remaining-=c['steps']
    assert work['remaining']==remaining and work['steps']==sum(f['steps'] for f in frames)+sum(c['steps'] for c in contexts),'Saved-reference work mismatch'
    return count


def check_saved_stream(graph,lines,class_names=None):
    """Validate the bounded comment grammar, scope and instruction attachment."""
    import re,ast
    expected=collections.defaultdict(list)
    for c in graph.get('saved_reference_contexts',[]):
        for o in c['observations']:expected[o['site']].append((c,o))
    pattern=re.compile(r'^\s*// async restored-reference: load result X(\d+) heap class (0x[0-9a-f]+)(?: \(("(?:[^"\\\x00-\x1f\x7f]|\\.)*")\))? \[conditional: delivery at await (0x[0-9a-f]+); store (0x[0-9a-f]+) to FP(-?\d+|\+\d+); preserved through await (0x[0-9a-f]+); normal call fallthrough; successful SDK resumes; value/error-preserving callbacks; reference only\]$')
    instruction=re.compile(r'^\s*//\s*(0x[0-9a-f]+):\s+[a-z][a-z0-9.]*\b')
    pending=[];seen=collections.Counter();required=collections.Counter()
    for line in lines:
        if line.lstrip().startswith('// async restored-reference'):
            m=pattern.fullmatch(line.rstrip('\n'));assert m,'Malformed or unscoped restored-reference note'
            pending.append(m);continue
        word=instruction.match(line)
        if word:
            pc=int(word[1],16)
            for m in pending:
                matches=[(c,o) for c,o in expected[pc] if o['register']==int(m[1]) and c['class_id']==int(m[2],16) and c['source_await']==int(m[4],16) and o['store']==int(m[5],16) and o['slot']==int(m[6]) and o['suspension']==int(m[7],16)]
                assert len(matches)==1,'Restored-reference note differs from its scoped evidence'
                c,o=matches[0]
                if m[3] and class_names and c['class_id'] in class_names:assert ast.literal_eval(m[3])==class_names[c['class_id']]
                seen[pc,c['source_await']]+=1
            pending=[]
            for c,o in expected[pc]:required[pc,c['source_await']]+=1
    assert not pending and seen==required,'Missing or duplicate restored-reference note'
    return seen


def check_saved_output(graph,output):
    import json
    from native_assembly import native_assembly_streams
    from check_call_result_notes import metadata_class_names
    path=output/'blutter_frida.js';names=metadata_class_names(path.read_text()) if path.exists() else None
    manifest=json.loads((output/'snapshot_code.json').read_text());seen=collections.Counter()
    for _,stream in native_assembly_streams(output,manifest):seen.update(check_saved_stream(graph,stream,names))
    assert sum(seen.values())==sum(len(c['observations']) for c in graph.get('saved_reference_contexts',[]))
    return sum(seen.values())
