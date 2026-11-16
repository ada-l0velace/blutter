"""Audit async value-completion evidence against original bytes and typed VM data.

These summaries describe supplied completion operands over covered payload entries.
They never describe the synchronous return value or bind a Future to an await.
"""
import collections
import struct

FIELDS = ('completion_exception_contracts', 'completion_bodies', 'completion_summaries', 'completion_work')
SCOPE = 'covered_payload_entries_successful_value_completions'


def check_completions(graph, audit, read):
    if graph.get('format', 0) < 37:
        return 0
    import capstone as cs
    from capstone import arm64 as a
    from input_origins import check_origins
    from check_snapshot_annotations import decode_payload
    md = cs.Cs(cs.CS_ARCH_ARM64, cs.CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    summaries = graph['completion_summaries']
    exceptions = graph['completion_exception_contracts']
    bodies = graph['completion_bodies']
    assert len({v['payload'] for v in summaries}) == len(summaries)
    assert len({v['payload'] for v in bodies}) == len(bodies) == len(summaries)
    assert len({v['entry'] for v in exceptions}) == len(exceptions)
    if summaries or exceptions:
        assert audit is not None, 'Completion evidence requires a typed VM audit'
    typed_exceptions = {v['entry']: v for v in (audit or {}).get('completion_exception_identities', [])}
    references = {(v['kind'], v['tail_only']): bytes.fromhex(v['bytes']) for v in (audit or {}).get('completion_exception_references', [])}
    assert exceptions == sorted(typed_exceptions.values(), key=lambda v: v['entry']), 'Exception identity audit mismatch'
    for e in exceptions:
        raw = references[(e['kind'], e['tail_only'])]
        assert 0 < len(raw) <= 1 << 20 and e['end'] - e['entry'] == len(raw)
        assert read(e['entry'], len(raw)) == raw, 'Exception helper bytes mismatch'
    ex = {v['entry']: v for v in exceptions}
    typed_bodies = {v['payload']: v for v in (audit or {}).get('completion_bodies', [])}
    body_map = {v['payload']: v for v in bodies}
    nodes = {v['start']: v for v in graph['nodes']}
    asyncs = {v['entry']: v['operation'] for v in graph['async_contracts']}
    complete = ('complete_value', 'complete_value_or_future')
    metadata = graph['receiver_metadata']
    allocations = dict(metadata['allocation_returns']) if metadata['allocation_result_register'] == 'x0' else {}
    natives = {v[0]: v[1] for v in metadata['native_return_classes']}
    stubs = {v[0]: v[1] for v in metadata['sdk_stub_return_classes']}
    pool_classes = dict((audit or {}).get('pool_heap_classes', []))
    nonreturning = dict(metadata['nonreturning_calls'])
    pool_loads = {v['site']: v['pool_index'] for v in graph['references'] if v['kind'] == 'pool' and v['access'] == 'load' and v['width'] == 8 and v['pool_index'] is not None}
    entries = set(metadata.get('entries', []))
    entries.update(n['start'] for n in nodes.values())
    entries.update(v['address'] for n in nodes.values() for v in n.get('names', []))
    entries.update(e['target'] for e in graph['edges'] if e.get('target') is not None)
    entries.update(v for v in graph.get('dispatch_table', {}).get('entries', []) if v is not None)
    # Native RegisterEntries sees every decoded direct branch/call in the image,
    # not merely edges retained by higher-level analysis.
    def target(i):
        return i.operands[-1].imm if i.operands and i.operands[-1].type == a.ARM64_OP_IMM else None
    def unconditional(i):
        return i.id == a.ARM64_INS_B and i.cc in (a.ARM64_CC_INVALID, a.ARM64_CC_AL)
    expected = {}
    for n in nodes.values():
        if not n['decoded']:
            continue
        sites = {}
        for index, (word,) in enumerate(struct.iter_unpack('<I', read(n['start'], n['end']-n['start']))):
            pc = n['start'] + index*4
            shift, bits = ((0,26) if word&0x7c000000 == 0x14000000 else
                          (5,19) if word&0xff000010 == 0x54000000 or word&0x7e000000 == 0x34000000 else
                          (5,14) if word&0x7e000000 == 0x36000000 else (0,0))
            if not bits:
                continue
            delta = (word>>shift)&((1<<bits)-1)
            if delta&(1<<(bits-1)):
                delta -= 1<<bits
            dest = pc+delta*4
            entries.add(dest)
            if word&0xfc000000 == 0x14000000 and asyncs.get(dest) in complete:
                sites[pc] = asyncs[dest]
        if sites and n['end']-n['start'] <= 16384*4:
            expected[n['start']] = sites
    assert set(expected) == {s['payload'] for s in summaries}, 'Missing or unexpected completion payload'
    total = 0
    all_origins, handler_entries = [], set()
    for s in summaries:
        total += s['steps']
        start, end = s['payload'], s['end']
        node = nodes[start]
        assert end == node['end'] and s['scope'] == SCOPE
        body = body_map[start]
        if start in typed_bodies:
            assert body == typed_bodies[start], 'Handler metadata mismatch'
        else:
            assert body == dict(payload=start, end=0, available=False, async_error_handler=False, handlers=[]), 'Invented Code metadata'
        if s['status'] == 'step_limit':
            assert not s['closed'] and s['exact_class'] is None
            continue
        insns = decode_payload(md, read(start, end-start), start)
        assert len(insns)*4 == end-start
        pcs = {i.address: i for i in insns}
        valid_metadata = body['available'] and body['end'] == end and len(body['handlers']) <= 1024 and body['handlers'] == sorted(set(body['handlers'])) and all(start <= pc < end and pc % 4 == 0 for pc in body['handlers'])
        local_entries = sorted({start} | {v for v in entries if start <= v < end and v % 4 == 0} | (set(body['handlers']) if valid_metadata else set()))
        assert s['entries'] == local_entries, ('Payload entry coverage mismatch',hex(start))
        assert [v['site'] for v in s['completions']] == sorted(expected[start]), 'Completion-site coverage mismatch'
        origin_rows = []
        for v in s['completions']:
            assert v['operation'] == expected[start][v['site']] and v['callee'] == target(pcs[v['site']])
            origin_rows.append(dict(site=v['site'], payload=start, role='completion_operand', index=None, register=0, sp_offset=None,
                condition='normal_fallthrough', chain=[dict(relation='input', source=v['source'], stop=v['stop'], steps=v['trace_steps'], pool_index=v['pool_index'])]))
            source = v['source']
            cid, basis, value, pool = None, 'unproved', 'unknown', None
            if source:
                kind = source['kind']
                if kind == 'runtime_null':
                    cid, basis = metadata['null_class_id'], 'sdk_null_register'
                    assert metadata['null_register'] == 'x22'
                elif kind == 'literal':
                    basis, value = 'original_word', 'word'
                elif kind == 'post_call_x0':
                    callee = source['callee']
                    for table, label in ((allocations, 'allocation'), (natives, 'sdk_native_result'), (stubs, 'sdk_stub_result')):
                        if callee in table:
                            cid, basis = table[callee], label
                            break
                elif kind == 'load' and source['site'] in pool_loads:
                    pool = pool_loads[source['site']]
                    cid, basis = pool_classes.get(pool), 'checked_pool_object'
                if cid is not None:
                    assert type(cid) is int and cid > 0
                    value = 'null' if cid == metadata['null_class_id'] else 'heap_class'
            assert (v['class_id'], v['basis'], v['value'], v['pool_index']) == (cid, basis, value, pool), 'Completion value classification mismatch'
        all_origins.extend(origin_rows)
        if valid_metadata:
            handler_entries.update(body['handlers'])
        trace_steps = sum(v['trace_steps'] for v in s['completions'])
        pending = collections.deque(local_entries)
        reached, initializations, exits = set(), set(), []
        closed = True
        def escape(i, kind, dest=None):
            nonlocal closed
            exits.append(dict(site=i.address, target=dest, kind=kind))
            closed = False
        while pending:
            pc = pending.popleft()
            if pc in reached:
                continue
            reached.add(pc)
            i = pcs[pc]
            dest = target(i)
            call, jump = i.group(cs.CS_GRP_CALL), i.group(cs.CS_GRP_JUMP)
            if (call or unconditional(i)) and dest in ex and (not ex[dest]['tail_only'] or unconditional(i)):
                exits.append(dict(site=pc, target=dest, kind='exception:'+ex[dest]['kind']))
                continue
            if pc in expected[start]:
                continue
            if i.group(cs.CS_GRP_RET):
                escape(i, 'ordinary_return');continue
            if i.group(cs.CS_GRP_INT) or i.id == a.ARM64_INS_UDF:
                escape(i, 'unmodeled_terminal');continue
            if call:
                op = asyncs.get(dest)
                if op == 'init_async':
                    initializations.add(pc)
                elif op is not None and op not in ('await', 'await_with_type_check'):
                    escape(i, 'unsupported_async_call', dest);continue
                if dest in nonreturning:
                    exits.append(dict(site=pc, target=dest, kind='exception:matched_nonreturning'));continue
            elif jump:
                if dest is None:
                    escape(i, 'indirect_exit');continue
                if dest in pcs:
                    pending.append(dest)
                else:
                    escape(i, 'escaping_branch', dest)
                if unconditional(i):
                    continue
            if pc+4 in pcs:
                pending.append(pc+4)
            else:
                escape(i, 'fallthrough_exit')
        assert s['reached'] == sorted(reached) and s['initializations'] == sorted(initializations), ('Reachability mismatch',hex(start),set(s['reached'])^reached,s['initializations'],initializations)
        assert s['exits'] == sorted(exits, key=lambda v: v['site']), 'Exit coverage mismatch'
        closed &= all(v['site'] in reached for v in s['completions'])
        classes = sorted({v['class_id'] for v in s['completions'] if v['value'] == 'heap_class'})
        null = any(v['value'] == 'null' for v in s['completions'])
        unknown = any(v['value'] not in ('null', 'heap_class') for v in s['completions'])
        forward = any(v['operation'] == 'complete_value_or_future' for v in s['completions'])
        exact = None
        status = ('missing_exception_metadata' if not valid_metadata else
                  'no_matched_initialization' if not initializations else
                  'open_control_flow' if not closed else 'value_or_future' if forward else
                  'unknown_value' if unknown else 'null_only' if not classes else
                  'mixed_classes' if len(classes) > 1 else 'nullable_class' if null else 'exact_heap_class')
        if status == 'exact_heap_class':
            exact = classes[0]
        assert (s['status'], s['exact_class'], s['closed'], s['observed_classes'], s['observed_null'], s['unknown_value'], s['value_or_future']) == (
            status, exact, bool(closed and valid_metadata and initializations), classes, null, unknown, forward), 'Invalid completion summary'
        assert s['steps'] == len(insns)+trace_steps+len(reached), 'Completion work accounting mismatch'
    view = dict(graph, call_input_origins=all_origins, input_object_catalog=[])
    trace_steps = sum(v['chain'][0]['steps'] for v in all_origins)
    view['input_origin_work'] = dict(limit=2000000, steps=trace_steps, remaining=2000000-trace_steps)
    check_origins(view, audit, read, allow_runtime_null=True, extra_entries=handler_entries)
    work = graph['completion_work']
    assert work == dict(limit=2000000, steps=total, remaining=2000000-total) and 0 <= total <= 2000000
    return len(summaries)
