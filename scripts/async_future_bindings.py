"""Original-byte checks for conditional async completion links.

A traced call result is a reference identity, not a heap-preservation contract.
Custom value/error callbacks and unchecked generic await acceptance stay outside
an unconditional delivered-class claim.
"""
import bisect
import collections

FIELDS = ('future_binding_abi', 'future_binding_bodies', 'future_producers',
          'await_future_bindings', 'future_binding_work')
CONDITIONS = ['normal_producer_return', 'successful_await_resume', 'value_and_error_preserving_sdk_callbacks']
LIMIT = 2000000


def _candidate(row):
    return row['closed'] and row['status'] in ('exact_heap_class', 'null_only', 'value_or_future')


def _metadata(body, start, end):
    return (body['available'] and body['end'] == end and len(body['handlers']) <= 1024 and
            body['handlers'] == sorted(set(body['handlers'])) and
            all(start <= pc < end and pc % 4 == 0 for pc in body['handlers']))


def _frame_proof(insns, entry, summary, body, slot, asyncs, exceptions, nonreturning, remaining, *, reference_entries=None):
    """Rebuild the entry-specific protocol from original instructions, not names."""
    import capstone as cs
    from capstone import arm64 as a
    start, end = summary['payload'], summary['end']
    def fail(status, steps=0):
        row=dict(status=status, steps=steps, before_init=[], after_init=[], traps=[], boundaries=[])
        if reference_entries is not None:row['points']=[]
        return row
    if reference_entries is not None and not body['async_error_handler']:
        return fail('missing_async_handler'),remaining
    if reference_entries is not None and any((o.type==a.ARM64_OP_REG and o.reg in (a.ARM64_REG_SP,a.ARM64_REG_WSP)) or (o.type==a.ARM64_OP_MEM and o.mem.base==a.ARM64_REG_SP) for i in insns for o in i.operands):
        return fail('native_stack_access'),remaining
    if not (_candidate(summary) if reference_entries is None else summary['closed']):
        return fail('completion_unproved'), remaining
    if not _metadata(body, start, end):
        return fail('missing_producer_metadata'), remaining
    if len(summary['initializations']) != 1:
        return fail('ambiguous_initialization'), remaining
    if not insns or len(insns) > 16384 or insns[0].address != start or len(insns)*4 != end-start or not start <= entry < end or entry % 4:
        return fail('unsupported_entry'), remaining
    pcs = {i.address: i for i in insns}
    def number(reg):
        name = insns[0].reg_name(reg)
        return 29 if name == 'fp' else 30 if name == 'lr' else int(name[1:]) if name and name[0] in 'xw' and name[1:].isdigit() else -1
    def width(reg):
        name = insns[0].reg_name(reg)
        return 16 if name and name[0] == 'q' else 8 if name and name[0] in 'xd' or reg in (a.ARM64_REG_FP, a.ARM64_REG_LR, a.ARM64_REG_XZR) else 4 if name and name[0] in 'ws' or reg == a.ARM64_REG_WZR else 0
    def target(i):
        return i.operands[-1].imm if i.operands and i.operands[-1].type == a.ARM64_OP_IMM else None
    def unconditional(i):
        return i.id == a.ARM64_INS_B and i.cc in (a.ARM64_CC_INVALID, a.ARM64_CC_AL)
    def add(x, y):
        value = x+y if x is not None else None
        return value if value is not None and -(1 << 63) <= value < 1 << 63 else None
    def frame_step(i, initialized, frame):
        anchored, sp, saved, exact, cleared = frame
        o = i.operands
        if i.id == a.ARM64_INS_MOV and len(o) == 2 and not i.writeback and not i.update_flags and o[0].type == o[1].type == a.ARM64_OP_REG and o[0].reg == a.ARM64_REG_X29 and o[1].reg == a.ARM64_REG_X15:
            return ('frame_register_modified', frame) if initialized else ('unproved_frame_anchor', frame) if not saved else ('', (True, 0, True, True, False))
        if (i.id == a.ARM64_INS_STP and len(o) == 3 and i.writeback and not i.update_flags and
            o[0].type == o[1].type == a.ARM64_OP_REG and o[0].reg == a.ARM64_REG_X29 and o[1].reg == a.ARM64_REG_X30 and
            o[2].type == a.ARM64_OP_MEM and o[2].mem.base == a.ARM64_REG_X15 and not o[2].mem.index and o[2].mem.disp == -16):
            return ('nested_frame', frame) if initialized else ('', (False, None, True, False, False))
        if i.group(cs.CS_GRP_CALL) or i.group(cs.CS_GRP_JUMP) or i.id in (a.ARM64_INS_NOP, a.ARM64_INS_CMP, a.ARM64_INS_CMN, a.ARM64_INS_TST):
            return '', frame
        writes = {number(r) for r in i.regs_write}
        writes.update(number(v.reg) for v in o if v.type == a.ARM64_OP_REG and v.access & cs.CS_AC_WRITE)
        writes.update(number(v.mem.base) for v in o if v.type == a.ARM64_OP_MEM and i.writeback)
        if 22 in writes:
            return 'runtime_null_register_modified',frame
        if 29 in writes:
            if initialized:
                return 'frame_register_modified', frame
            anchored, sp, saved, exact, cleared = False, None, False, False, False
        if (i.id in (a.ARM64_INS_ADD, a.ARM64_INS_SUB) and len(o) == 3 and not i.writeback and not i.update_flags and
            o[0].type == o[1].type == a.ARM64_OP_REG and o[0].reg == o[1].reg == a.ARM64_REG_X15 and o[2].type == a.ARM64_OP_IMM and
            0 <= o[2].imm <= 1048576 and not o[2].shift.value):
            return '', (anchored, add(sp, o[2].imm*(1 if i.id == a.ARM64_INS_ADD else -1)), saved if anchored else False,exact,cleared)
        pair = i.id == a.ARM64_INS_STP
        stores = (a.ARM64_INS_STR, a.ARM64_INS_STUR, a.ARM64_INS_STRB, a.ARM64_INS_STURB, a.ARM64_INS_STRH, a.ARM64_INS_STURH)
        if pair or i.id in stores:
            if len(o) != (3 if pair else 2) or o[-1].type != a.ARM64_OP_MEM or any(v.type != a.ARM64_OP_REG for v in o[:-1]):
                return 'unsupported_frame_store', frame
            if anchored and any(number(v.reg) in (15, 29) for v in o[:-1]):
                return 'frame_address_escapes', frame
            m = o[-1].mem
            base = number(m.base)
            if base in (15, 29):
                if m.index or i.writeback and base != 15:
                    return 'unsupported_frame_store', frame
                size = 1 if i.id in (a.ARM64_INS_STRB, a.ARM64_INS_STURB) else 2 if i.id in (a.ARM64_INS_STRH, a.ARM64_INS_STURH) else width(o[0].reg)
                if not size or pair and width(o[1].reg) != size:
                    return 'unsupported_frame_store', frame
                if not initialized and base==15 and not exact:
                    cleared=False
                if not initialized and (base==29 or exact):
                    begin=m.disp if base==29 else add(sp,m.disp)
                    if begin is not None:
                        for part in range(2 if pair else 1):
                            at=add(begin,part*size)
                            stop=add(at,size)
                            if at is not None and stop is None:return 'unknown_stack_address',frame
                            if at is not None and at<slot+8 and stop>slot:
                                cleared=at==slot and size==8 and o[part].reg==a.ARM64_REG_X22
                control_end=add(m.disp,size*(2 if pair else 1))
                if control_end is None:return 'unknown_stack_address',frame
                if anchored and base==29 and m.disp<16 and control_end>0:
                    return 'frame_control_overwritten',frame
                if initialized:
                    offset = m.disp if base == 29 else add(sp, m.disp)
                    stop = add(offset, size*(2 if pair else 1))
                    if offset is None or stop is None:
                        return 'unknown_stack_address', frame
                    if base==15 and stop>slot:
                        return 'unproved_stack_write',frame
                    if base==29 and offset<slot+8 and stop>slot:
                        return 'suspend_state_overwritten',frame
                if i.writeback:
                    if not -256 <= m.disp < 0 or m.disp % 8:
                        return 'unsupported_stack_update', frame
                    sp = add(sp, m.disp)
            return '', (anchored, sp, saved,exact,cleared)
        loads = tuple(getattr(a, 'ARM64_INS_'+name) for name in ('LDR','LDUR','LDP','LDRB','LDURB','LDRH','LDURH','LDRSB','LDURSB','LDRSH','LDURSH','LDRSW','LDURSW','LDTR','LDTRB','LDTRH','LDTRSB','LDTRSH','LDTRSW'))
        if any(v.type == a.ARM64_OP_MEM and number(v.mem.base) in (15,29) for v in o) and (i.id not in loads or i.writeback):
            return 'unsupported_frame_memory', frame
        if anchored and any(v.type == a.ARM64_OP_REG and v.access & cs.CS_AC_READ and number(v.reg) in (15,29) for v in o):
            return 'frame_address_escapes', frame
        if 15 in writes:
            sp = None;exact=False
            if not anchored:
                saved = False
        return '', (anchored, sp, saved,exact,cleared)
    def consumed_argument_address(i,load):
        o=i.operands
        if (load is None or i.id!=a.ARM64_INS_ADD or len(o)!=3 or i.writeback or i.update_flags or
            any(v.type!=a.ARM64_OP_REG for v in o) or not a.ARM64_REG_X0<=o[0].reg<=a.ARM64_REG_X14 or
            o[1].reg!=a.ARM64_REG_X29 or not a.ARM64_REG_W0<=o[2].reg<=a.ARM64_REG_W14 or
            o[2].ext!=a.ARM64_EXT_SXTW or o[2].shift.type!=a.ARM64_SFT_LSL or o[2].shift.value!=2):return False
        l=load.operands
        return (load.id in (a.ARM64_INS_LDR,a.ARM64_INS_LDUR) and len(l)==2 and not load.writeback and not load.update_flags and
                l[0].type==a.ARM64_OP_REG and l[0].reg==o[0].reg and l[1].type==a.ARM64_OP_MEM and
                l[1].mem.base==o[0].reg and not l[1].mem.index and 0<=l[1].mem.disp<=4096 and l[1].mem.disp%8==0)
    states, queue = {}, collections.deque()
    def push(pc, initialized, frame):
        if pc not in pcs:
            return False
        key = pc, initialized
        if key not in states:
            states[key] = frame; queue.append(key)
        else:
            old = states[key]
            merged = (old[0] and frame[0], max(old[1],frame[1]) if old[1] is not None and frame[1] is not None else None, old[2] and frame[2],
                      old[3] and frame[3] and old[1]==frame[1],old[4] and frame[4])
            if old != merged:
                states[key] = merged; queue.append(key)
        return True
    push(entry, False, (False, None, False, False, False))
    for pc in sorted(reference_entries or ()):
        if start<=pc<end:push(pc,False,(False,None,False,False,False))
    for handler in body['handlers']:
        push(handler, False, (True, None, False, False, False))
    before, after, boundaries, traps, steps = set(), set(), {}, set(), 0
    while queue:
        if remaining == 0:
            return fail('step_limit', steps), remaining
        remaining -= 1; steps += 1
        pc, initialized = queue.popleft()
        frame = states[pc, initialized]
        i = pcs[pc]; dest = target(i)
        if not initialized and not frame[4] and i.group(cs.CS_GRP_CALL):
            return fail('uninitialized_suspend_state',steps),remaining
        if i.id==a.ARM64_INS_BRK:
            traps.add(pc);continue
        (after if initialized else before).add(pc)
        ex = exceptions.get(dest)
        if (i.group(cs.CS_GRP_CALL) or unconditional(i)) and ex and (not ex['tail_only'] or unconditional(i)):
            continue
        if i.group(cs.CS_GRP_CALL) and dest in nonreturning:
            continue
        op = asyncs.get(dest)
        if i.group(cs.CS_GRP_CALL) and op == 'init_async':
            if pc != summary['initializations'][0] or initialized:
                return fail('repeated_initialization', steps), remaining
            if not frame[0] or frame[1] is None or frame[1] > slot:
                return fail('unproved_frame_anchor', steps), remaining
            if pc+4 == end:
                return fail('escaping_control_flow', steps), remaining
            push(pc+4, True, frame);continue
        if unconditional(i) and op in ('complete_value','complete_value_or_future') or i.group(cs.CS_GRP_CALL) and op in ('await','await_with_type_check'):
            if not initialized:
                return fail('initialization_bypassed', steps), remaining
            if not frame[0] or frame[1] is None or frame[1] > slot:
                return fail('unproved_stack_boundary', steps), remaining
            boundaries[pc] = op
            if unconditional(i):
                continue
        if initialized or not consumed_argument_address(i,pcs.get(pc+4)):
            invalid, frame = frame_step(i, initialized, frame)
            if invalid:
                return fail(invalid, steps), remaining
        if i.group(cs.CS_GRP_RET) or i.group(cs.CS_GRP_INT) or i.id == a.ARM64_INS_UDF:
            return fail('unmodeled_exit', steps), remaining
        if i.group(cs.CS_GRP_JUMP) and not i.group(cs.CS_GRP_CALL):
            if dest is None or not push(dest, initialized, frame):
                return fail('escaping_control_flow', steps), remaining
            if unconditional(i):
                continue
        if pc+4 == end:
            return fail('escaping_control_flow', steps), remaining
        push(pc+4, initialized, frame)
    if not boundaries:
        return fail('no_return_boundary', steps), remaining
    row=dict(status='matched_async_frame', steps=steps, before_init=sorted(before), after_init=sorted(after),traps=sorted(traps),
                boundaries=[dict(site=pc,operation=op) for pc,op in sorted(boundaries.items())])
    if reference_entries is not None:row['points']=[[pc,frame[1],frame[3]] for (pc,initialized),frame in sorted(states.items()) if initialized and frame[0] and frame[1] is not None and (pc,False) not in states]
    return row,remaining


def check_future_bindings(graph, audit, read):
    if graph.get('format',0) < 38:
        return 0
    import capstone as cs
    from check_snapshot_annotations import decode_payload
    from input_origins import check_origins
    abi = graph['future_binding_abi']
    assert type(abi['supported']) is bool
    if abi['supported']:
        assert audit is not None and abi == audit['future_binding_abi'], 'Future ABI differs from matching SDK audit'
        assert graph['receiver_metadata']['word_return_register'] == 'x0'
        assert type(abi['suspend_state_offset']) is int and -4096 <= abi['suspend_state_offset'] <= -8 and abi['suspend_state_offset'] % 8 == 0
    else:
        assert abi == dict(supported=False,suspend_state_offset=0)
    inputs = graph['await_future_bindings'];producers = graph['future_producers'];bodies = graph['future_binding_bodies']
    if not abi['supported']:
        assert inputs==producers==bodies==[]
        assert graph['future_binding_work']==dict(limit=LIMIT,remaining=LIMIT,steps=0,trace_steps=0,producer_steps=0,resolution_steps=0,
            producer_limit=4096,chain_limit=8,byte_limit=8388608,bytes=0)
        return 0
    assert len({v['site'] for v in inputs}) == len(inputs)
    assert [v['entry'] for v in producers] == sorted({v['entry'] for v in producers}) and len(producers) <= 4096
    assert [v['payload'] for v in bodies] == sorted({v['payload'] for v in bodies})
    bodymap = {v['payload']:v for v in bodies}
    typed = {v['payload']:v for v in (audit or {}).get('completion_bodies',[])}
    for b in bodies:
        assert b == typed.get(b['payload'],dict(payload=b['payload'],end=0,available=False,async_error_handler=False,handlers=[])), 'Future handler metadata mismatch'
    awaits = {v['site']:v for v in graph['async_boundaries'] if v['operation'] in ('await','await_with_type_check')}
    assert [v['site'] for v in inputs] == (sorted(awaits) if abi['supported'] else []), 'Missing or unexpected await input'
    source_rows, handlers = [], set()
    nodes = {n['start']:n for n in graph['nodes']}
    for v in inputs:
        b = awaits[v['site']]
        assert all(v[k] == b[k] for k in ('site','payload','callee','operation','resume_site'))
        body = bodymap[v['payload']];n = nodes[v['payload']]
        valid_body = _metadata(body,n['start'],n['end'])
        expected_status = 'unsupported_input' if n['end']-n['start']>16384*4 else 'missing_caller_metadata' if not valid_body else 'no_successful_continuation' if b['resume_site'] is None else None
        if expected_status:
            assert v['input_status'] == expected_status and v['source'] is None and v['trace_steps'] == 0
        else:
            assert v['input_status'] in ('observed','step_limit')
            if v['input_status'] == 'step_limit':
                assert v['source'] is None and v['trace_steps'] == 0
        if valid_body:
            handlers.update(body['handlers'])
        source_rows.append(dict(site=v['site'],payload=v['payload'],role='await_input',index=None,register=0,sp_offset=None,
            condition='normal_fallthrough',chain=[dict(relation='input',source=v['source'],stop=v['stop'],steps=v['trace_steps'],pool_index=None)]))
    trace_steps = sum(v['trace_steps'] for v in inputs)
    view = dict(graph,call_input_origins=source_rows,input_object_catalog=[],input_origin_work=dict(limit=LIMIT,steps=trace_steps,remaining=LIMIT-trace_steps))
    check_origins(view,audit,read,extra_entries=handlers)
    summaries = {s['payload']:s for s in graph['completion_summaries']};starts = sorted(summaries)
    def summary_at(entry):
        pos = bisect.bisect_right(starts,entry)-1
        return summaries[starts[pos]] if pos >= 0 and entry < summaries[starts[pos]]['end'] else None
    cached, byte_count = set(),0
    if abi['supported']:
        for s in graph['completion_summaries']:
            size = s['end']-s['payload']
            if _candidate(s) and size <= 16384*4 and size <= 8388608-byte_count:
                cached.add(s['payload']);byte_count += size
    asyncs = {v['entry']:v['operation'] for v in graph['async_contracts']}
    exceptions = {v['entry']:v for v in graph['completion_exception_contracts']}
    nonreturning = dict(graph['receiver_metadata']['nonreturning_calls'])
    md = cs.Cs(cs.CS_ARCH_ARM64,cs.CS_MODE_LITTLE_ENDIAN);md.detail=True
    published = {v['entry']:v for v in producers};expected = {};remaining = LIMIT-trace_steps
    pending = {v['source']['callee'] for v in inputs if v['source'] and v['source']['kind'] == 'post_call_x0' and v['source']['callee'] is not None}
    while pending and len(expected) < 4096:
        entry = min(pending);pending.remove(entry)
        if entry in expected:
            continue
        s = summary_at(entry)
        row = dict(entry=entry,payload=s['payload'] if s else 0,end=s['end'] if s else 0,
                   status='unknown',value_status='unknown',class_id=None,null_value=False,steps=0,before_init=[],after_init=[],traps=[],boundaries=[],forwards=[])
        if s is None:
            row['status'] = 'no_completion_summary'
        elif not _candidate(s):
            row['status'] = 'completion_unproved'
        elif s['payload'] not in cached:
            row['status'] = 'producer_byte_limit'
        elif s['payload'] not in bodymap:
            row['status'] = 'missing_producer_metadata'
        else:
            insns = decode_payload(md,read(s['payload'],s['end']-s['payload']),s['payload'])
            fields,remaining = _frame_proof(insns,entry,s,bodymap[s['payload']],abi['suspend_state_offset'],asyncs,exceptions,nonreturning,remaining)
            row.update(fields)
            if row['status'] == 'matched_async_frame':
                for value in s['completions']:
                    source = value['source']
                    if value['operation'] == 'complete_value_or_future' and source and source['kind'] == 'post_call_x0' and source['callee'] is not None:
                        row['forwards'].append(dict(completion=value['site'],call=source['site'],producer=source['callee']))
                        if source['callee'] not in expected:
                            pending.add(source['callee'])
        expected[entry] = row
    assert set(expected) == set(published), 'Producer identity coverage mismatch'
    producer_steps = LIMIT-trace_steps-remaining
    visiting = set()
    def resolve(entry,depth):
        nonlocal remaining
        if entry not in expected or expected[entry]['status'] != 'matched_async_frame':
            return False
        row = expected[entry]
        if row['value_status'] != 'unknown':
            return row['value_status'] == 'conditional_value'
        if not remaining:
            row['value_status']='step_limit';return False
        remaining -= 1
        if depth >= 8:
            row['value_status']='chain_limit';return False
        if entry in visiting:
            row['value_status']='cyclic_forwarding';return False
        visiting.add(entry);agreed=None;status='conditional_value'
        for value in summary_at(entry)['completions']:
            if not remaining:
                status='step_limit';break
            remaining -= 1;cid=None
            if value['operation']=='complete_value' and value['class_id'] is not None:
                cid=value['class_id']
            elif value['operation']=='complete_value_or_future' and value['value']=='null' and value['class_id']==graph['receiver_metadata']['null_class_id']:
                cid=value['class_id']
            else:
                f=next((f for f in row['forwards'] if f['completion']==value['site']),None)
                if f and resolve(f['producer'],depth+1):cid=expected[f['producer']]['class_id']
            if cid is None:status='completion_value_unproved';break
            if agreed is not None and agreed!=cid:status='conflicting_completion_values';break
            agreed=cid
        visiting.remove(entry);row['value_status']=status
        if status=='conditional_value' and agreed is not None:
            row['class_id']=agreed;row['null_value']=agreed==graph['receiver_metadata']['null_class_id'];return True
        return False
    for entry in sorted(expected):resolve(entry,0)
    if expected!=published:
        differences=[]
        for entry,row in expected.items():
            actual=published[entry]
            for key,value in row.items():
                if value!=actual.get(key):
                    differences.append((hex(entry),key,value if not isinstance(value,list) else len(value),actual.get(key) if not isinstance(actual.get(key),list) else len(actual[key])))
        raise AssertionError(('Producer protocol/completion proof mismatch',differences[:4]))
    assert set(bodymap)=={v['payload'] for v in inputs}|{v['payload'] for v in producers if v['payload']},'Unexpected Future body catalogue'
    for v in inputs:
        call=producer=payload=cid=None;value='unknown';status=v['input_status']
        if status=='observed':
            source=v['source']
            if not source or source['kind']!='post_call_x0' or source['callee'] is None:
                status='producer_origin_unproved'
            else:
                call,producer=source['site'],source['callee'];p=expected.get(producer)
                if p is None:status='producer_limit'
                else:
                    payload=p['payload'] or None
                    status=(p['status'] if p['status']!='matched_async_frame' else
                            'typed_await_delivery_unproved' if v['operation']=='await_with_type_check' else
                            p['value_status'] if p['value_status']!='conditional_value' else 'conditional_delivery')
                    if status=='conditional_delivery':
                        cid=p['class_id'];value='null' if p['null_value'] else 'heap_class'
        assert (v['call'],v['producer'],v['producer_payload'],v['class_id'],v['value'],v['status'],v['conditions']) == (
            call,producer,payload,cid,value,status,CONDITIONS if status=='conditional_delivery' else []),'Unscoped or incorrect await delivery'
    work=graph['future_binding_work']
    assert work==dict(limit=LIMIT,remaining=remaining,steps=LIMIT-remaining,trace_steps=trace_steps,producer_steps=producer_steps,
        resolution_steps=LIMIT-remaining-trace_steps-producer_steps,producer_limit=4096,chain_limit=8,byte_limit=8388608,bytes=byte_count),'Future work accounting mismatch'
    return len(inputs)


def check_binding_stream(graph, lines, class_names=None):
    """Check scoped notes and their original successful-continuation addresses."""
    import ast
    import re
    expected={v['site']:v for v in graph.get('await_future_bindings',[]) if v['status']=='conditional_delivery'}
    assert all(v['conditions']==CONDITIONS for v in expected.values()),'Async note lacks its conditions'
    by_resume={v['resume_site']:v['site'] for v in expected.values()}
    note=re.compile(r'^\s*// async delivered-value: X0 (heap class (0x[0-9a-f]+)|null)(?: \(("(?:[^"\\\x00-\x1f\x7f]|\\.)*")\))? \[conditional: Future from call (0x[0-9a-f]+) to (0x[0-9a-f]+); await (0x[0-9a-f]+); successful SDK resume; value/error-preserving callbacks; no ordinary return claim\]$')
    instruction=re.compile(r'^\s*//\s*(0x[0-9a-f]+):\s+[a-z][a-z0-9.]*\b')
    observed,required=collections.Counter(),collections.Counter();pending=[]
    for line in lines:
        if line.lstrip().startswith('// async delivered-value'):
            match=note.fullmatch(line.rstrip('\n'));assert match,'Malformed or unscoped async delivery note'
            site=int(match[6],16);v=expected[site]
            assert int(match[4],16)==v['call'] and int(match[5],16)==v['producer']
            assert (('null' if match[1]=='null' else 'heap_class'),int(match[2],16) if match[2] else v['class_id'])==(v['value'],v['class_id'])
            if match[3] and class_names is not None and v['class_id'] in class_names:
                assert ast.literal_eval(match[3])==class_names[v['class_id']],'Async value class display name mismatch'
            pending.append(site);observed[site]+=1
            continue
        match=instruction.match(line)
        if match:
            pc=int(match[1],16)
            assert all(expected[site]['resume_site']==pc for site in pending),'Async note attached to the wrong continuation'
            pending.clear()
            if pc in by_resume:required[by_resume[pc]]+=1
    assert not pending and observed==required,'Missing or duplicate async delivery note'
    return observed


def check_binding_output(graph,output):
    import json
    from native_assembly import native_assembly_streams
    from check_call_result_notes import metadata_class_names
    script=output/'blutter_frida.js';names=metadata_class_names(script.read_text()) if script.exists() else None
    manifest=json.loads((output/'snapshot_code.json').read_text())
    observed=collections.Counter()
    for _,stream in native_assembly_streams(output,manifest):observed.update(check_binding_stream(graph,stream,names))
    assert set(observed)=={v['site'] for v in graph.get('await_future_bindings',[]) if v['status']=='conditional_delivery'},'Missing async value annotation'
    return sum(observed.values())
