"""Check saved Boolean identities and subsequent native branch consumers."""
from collections import Counter
import json
import struct
from field_branch_uses import check_stream as check_comments


FIELDS = ('decision_branch_abi', 'decision_reference_contexts',
          'decision_branch_uses', 'decision_branch_work')


def check_uses(graph, audit, read):
    if graph.get('format', 0) < 49:
        return 0
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, CS_GRP_JUMP, CS_GRP_CALL
    from capstone.arm64 import ARM64_OP_IMM
    from check_snapshot_annotations import decode_payload
    from saved_async_references import replay
    from async_future_bindings import _frame_proof
    from field_decisions import check_decisions
    check_decisions(graph,audit,read)
    from field_branch_uses import signed

    assert graph['decision_branch_abi'] == audit['decision_branch_abi']
    bit = graph['decision_branch_abi']['value_bit']
    contexts = graph['decision_reference_contexts']
    work = graph['decision_branch_work']
    assert work['steps'] == sum(c['steps'] for c in contexts)
    assert work['steps'] + work['remaining'] == 200000 and 0 <= work['remaining'] <= 200000
    assert type(work['complete']) is bool and len(contexts) <= 4096
    decisions = graph['field_decisions']
    wanted = sorted(range(len(decisions)), key=lambda n: (
        graph['joined_reference_contexts'][graph['field_branch_uses'][decisions[n]['branch_use']]['context']]['payload'], n))
    if bit is None or not 0 <= bit < 32:
        wanted = []
    assert [c['decision'] for c in contexts] == wanted[:len(contexts)]
    assert len(contexts) == len(wanted) or not work['complete']
    if not contexts:
        assert not graph['decision_branch_uses'] and not work['bytes']
        return 0
    decoder = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    decoder.detail = True
    frames = {f['payload']: f for f in graph['saved_reference_frames']}
    bodies = {b['payload']: b for b in graph['future_binding_bodies']}
    ends = {n['start']: n['end'] for n in graph['nodes']}
    entries = set(graph['receiver_metadata']['entries'])
    maps = {m['site']: m for m in graph['saved_reference_stack_maps']}
    assert graph['saved_reference_abi'] == audit['saved_reference_abi']
    typed_maps = {(m['payload'],m['site']):m for m in audit['saved_reference_stack_maps']}
    assert all(m == typed_maps.get((m['payload'],m['site'])) for m in maps.values())
    summaries = {c['payload']:c for c in graph['completion_summaries']}
    asyncs = {a['entry']: a['operation'] for a in graph['async_contracts']}
    exceptions = {e['entry']: e for e in graph['completion_exception_contracts']}
    nonreturning = dict(graph['receiver_metadata']['nonreturning_calls'])
    decoded = {}
    expected = []
    for ci, context in enumerate(contexts):
        decision = decisions[context['decision']]
        parent = graph['joined_reference_contexts'][graph['field_branch_uses'][decision['branch_use']]['context']]
        payload = parent['payload']
        assert context['payload'] == payload and frames[payload]['status'] == 'matched_async_frame'
        if payload not in decoded:
            code = read(payload, ends[payload]-payload)
            insns = list(decode_payload(decoder, code, payload))
            expected_frame,_ = _frame_proof(insns,payload,summaries[payload],bodies[payload],
                graph['future_binding_abi']['suspend_state_offset'],asyncs,exceptions,nonreturning,
                2000000,reference_entries=entries)
            assert all(frames[payload][k] == expected_frame[k] for k in ('status','steps','points'))
            barriers = entries | set(bodies[payload]['handlers'])
            for insn in insns:
                if ((insn.group(CS_GRP_JUMP) or insn.group(CS_GRP_CALL)) and insn.operands
                        and insn.operands[-1].type == ARM64_OP_IMM):
                    barriers.add(insn.operands[-1].imm)
            decoded[payload] = code, insns, barriers
        code, insns, barriers = decoded[payload]
        if context['status'] != 'checked':
            assert context['status'] in ('unsupported_control','region_limit','step_limit')
            assert not context['reloads']
            continue
        observations, visited = replay(insns, decision['site']+4,
            {site:(sp,exact) for site,sp,exact in frames[payload]['points']},
            maps, entries, set(bodies[payload]['handlers']), asyncs, exceptions, nonreturning,
            graph['saved_reference_abi']['first_local_offset'],
            graph['future_binding_abi']['suspend_state_offset'],
            local=dict(store=decision['site'], slot=decision['fp_offset']))
        assert visited <= 2048 and context['steps'] >= visited
        assert context['reloads'] == sorted(context['reloads'],key=lambda r:r['site'])
        for ri, reload in enumerate(context['reloads']):
            assert reload in observations, 'Decision reload lacks its all-path reaching definition'
            pc = reload['site']+4
            if pc >= ends[payload] or pc in barriers:
                continue
            word, = struct.unpack_from('<I', code, pc-payload)
            if (word & 0xfe00001f) != (0x36000000 | reload['register']) or ((word >> 19) & 31) != bit:
                continue
            target = pc + 4*signed((word >> 5) & 0x3fff,14)
            if not payload <= target < ends[payload] or pc+4 >= ends[payload]:
                continue
            nonzero = bool(word & (1<<24))
            expected.append(dict(context=ci,reload=ri,site=pc,
                                 true_target=pc+4 if nonzero else target,
                                 false_target=target if nonzero else pc+4))
    assert work['bytes'] == sum(len(code) for code,_,_ in decoded.values())
    assert graph['decision_branch_uses'] == expected, 'Boolean branch differs from original machine words'
    return len(expected)


def note(graph, use):
    context = graph['decision_reference_contexts'][use['context']]
    decision = graph['field_decisions'][context['decision']]
    reload = context['reloads'][use['reload']]
    return (f"decision branch: Boolean saved at {decision['site']:#x}; true -> {use['true_target']:#x}, "
            f"false -> {use['false_target']:#x} [conditional on reload {reload['site']:#x}; "
            f"owned tagged frame slot FP{reload['slot']:+d}; normal call fallthrough; successful SDK resumes]")


def expected_notes(graph):
    return Counter((u['site'], note(graph,u)) for u in graph['decision_branch_uses'])


def check_stream(stream, expected):
    return check_comments(stream, expected, prefix='decision branch:')


def check_output(graph, output):
    from native_assembly import native_assembly_streams
    expected = expected_notes(graph)
    seen = Counter()
    manifest = json.loads((output/'snapshot_code.json').read_text())
    for _,stream in native_assembly_streams(output,manifest):
        seen.update(check_stream(stream,expected))
    assert seen == expected, 'Missing or duplicate decision branch comments'
    return sum(seen.values())
