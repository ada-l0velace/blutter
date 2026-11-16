"""Check conditional reference reloads with bounded last-suspension alternatives."""
import collections
import re
from saved_async_references import replay
from async_future_bindings import CONDITIONS

FIELDS = ('joined_reference_contexts', 'joined_reference_work')
SCOPE = 'conditional_joined_reference_only'
LIMITS = dict(limit=200000, region_limit=2048, history_limit=8, context_limit=4096,
              body_limit=65536, byte_limit=8388608)


def validate_structure(graph):
    contexts = graph['joined_reference_contexts'];work = graph['joined_reference_work']
    assert all(work[k] == v for k, v in LIMITS.items())
    assert type(work['complete']) is bool and len(contexts) <= 4096
    assert work['steps'] == sum(c['steps'] for c in contexts)
    assert 0 <= work['remaining'] <= 200000 and work['steps'] + work['remaining'] == 200000
    assert type(work['history_overflows']) is int and 0 <= work['history_overflows'] <= work['steps'] * 2048
    assert type(work['bytes']) is int and 0 <= work['bytes'] <= 8388608
    parents = [c for c in graph['saved_reference_contexts'] if c['status'] == 'checked' and c['class_id'] != graph['receiver_metadata']['null_class_id']]
    if not graph['saved_reference_abi']['supported'] or not graph['future_binding_abi']['supported']:parents = []
    assert [(c['payload'], c['source_await'], c['class_id']) for c in contexts] == [(c['payload'], c['source_await'], c['class_id']) for c in parents[:len(contexts)]]
    assert len(contexts) == len(parents) or not work['complete']
    seeds = {(b['payload'], b['site']): b for b in graph['await_future_bindings']}
    frames = {f['payload']: f for f in graph['saved_reference_frames']}
    nodes = {n['start']: n for n in graph['nodes']};decoded = set()
    for c, parent in zip(contexts, parents):
        seed = seeds[c['payload'], c['source_await']]
        assert seed['status'] == 'conditional_delivery' and seed['value'] == 'heap_class' and seed['class_id'] == c['class_id'] and seed['conditions'] == CONDITIONS
        assert frames[c['payload']]['status'] == 'matched_async_frame'
        assert c['scope'] == SCOPE and c['status'] in {'checked', 'missing_caller_bytes', 'unsupported_resume', 'unsupported_control', 'region_limit', 'step_limit'}
        assert type(c['steps']) is int and 0 <= c['steps'] <= 200000
        if c['status'] != 'missing_caller_bytes':decoded.add(c['payload'])
        else:assert c['steps'] == 0
        if c['status'] != 'checked':assert not c['observations']
        else:assert type(seed['resume_site']) is int and c['payload'] <= seed['resume_site'] < nodes[c['payload']]['end'] and seed['resume_site'] % 4 == 0
        if c['status'] == 'step_limit':assert not work['complete']
        assert [o['site'] for o in c['observations']] == sorted({o['site'] for o in c['observations']})
        old_sites = {o['site'] for o in parent['observations']}
        for o in c['observations']:
            assert o['site'] not in old_sites
            assert type(o['register']) is int and 0 <= o['register'] < 15
            assert type(o['slot']) is int and -4096 <= o['slot'] <= graph['saved_reference_abi']['first_local_offset'] and o['slot'] % 8 == 0
            assert o['slot'] + 8 <= graph['future_binding_abi']['suspend_state_offset']
            for pc in [o['site'], o['store']]:assert type(pc) is int and c['payload'] <= pc < nodes[c['payload']]['end'] and pc % 4 == 0
            last = o['last_suspensions'];assert 2 <= len(last) <= 8
            assert all(x is None or type(x) is int and c['payload'] <= x < nodes[c['payload']]['end'] and x % 4 == 0 for x in last)
            assert last == [x or None for x in sorted({x or 0 for x in last})], 'Unknown history is not a no-await alternative'
    assert work['bytes'] == sum(nodes[p]['end'] - p for p in decoded)
    assert all(0 < nodes[p]['end'] - p <= 65536 for p in decoded)
    return contexts


def check_joined(graph, audit, read):
    if graph.get('format', 0) < 46:return 0
    import capstone as cs
    from check_snapshot_annotations import decode_payload
    contexts = validate_structure(graph)
    if not contexts:return 0
    assert audit is not None, 'Joined-reference evidence requires the matching SDK audit'
    assert graph['saved_reference_abi'] == audit['saved_reference_abi']
    typed = {(m['payload'], m['site']): m for m in audit['saved_reference_stack_maps']}
    maps = {m['site']: m for m in graph['saved_reference_stack_maps']}
    assert all(m == typed.get((m['payload'], m['site'])) for m in maps.values())
    frames = {f['payload']: f for f in graph['saved_reference_frames']}
    bodies = {b['payload']: b for b in graph['future_binding_bodies']}
    nodes = {n['start']: n for n in graph['nodes']}
    seeds = {(b['payload'], b['site']): b for b in graph['await_future_bindings']}
    entries = set(graph['receiver_metadata']['entries'])
    asyncs = {a['entry']: a['operation'] for a in graph['async_contracts']}
    exceptions = {e['entry']: e for e in graph['completion_exception_contracts']}
    nonreturning = dict(graph['receiver_metadata']['nonreturning_calls'])
    decoder = cs.Cs(cs.CS_ARCH_ARM64, cs.CS_MODE_LITTLE_ENDIAN);decoder.detail = True
    decoded = {};count = 0
    for c in contexts:
        if c['status'] != 'checked':continue
        payload = c['payload']
        if payload not in decoded:decoded[payload] = list(decode_payload(decoder, read(payload, nodes[payload]['end'] - payload), payload))
        seed = seeds[payload, c['source_await']]
        observations, visited = replay(decoded[payload], seed['resume_site'],
            {pc: (sp, exact) for pc, sp, exact in frames[payload]['points']}, maps, entries,
            set(bodies[payload]['handlers']), asyncs, exceptions, nonreturning,
            graph['saved_reference_abi']['first_local_offset'], graph['future_binding_abi']['suspend_state_offset'], joined=True)
        assert visited <= 2048 and c['steps'] >= visited
        for o in c['observations']:assert o in observations, 'Joined reference lacks an all-path definition/history proof'
        count += len(c['observations'])
    return count


def note(context, observation):
    o = observation
    alternatives = ', '.join('no additional await' if x is None else f'{x:#x}' for x in o['last_suspensions'])
    return (f"async joined-reference: load result X{o['register']} heap class {context['class_id']:#x} "
        f"[conditional: delivery at await {context['source_await']:#x}; store {o['store']:#x} to FP{o['slot']:+d}; "
        f'last suspension alternatives since store {{{alternatives}}}; normal call fallthrough; '
        'successful SDK resumes; value/error-preserving callbacks; reference only]')


def check_stream(graph, stream):
    expected = collections.defaultdict(list)
    for c in graph.get('joined_reference_contexts', []):
        for o in c['observations']:expected[o['site']].append(note(c, o))
    pending = [];seen = collections.Counter()
    for line in stream:
        if 'async joined-reference:' in line:
            assert re.match(r'^\s*// async joined-reference:', line);pending.append(line.strip()[3:])
        m = re.match(r'^\s*// (0x[0-9a-f]+):', line)
        if m:
            pc = int(m[1], 16);wanted = collections.Counter(expected[pc])
            assert collections.Counter(pending) == wanted, 'Missing, duplicate or misplaced joined-reference comment'
            seen.update((pc, text) for text in pending)
            assert all(seen[pc, text] == n for text, n in wanted.items());pending = []
    assert not pending
    return seen


def check_output(graph, output):
    import json
    from native_assembly import native_assembly_streams
    validate_structure(graph);seen = collections.Counter()
    manifest = json.loads((output/'snapshot_code.json').read_text())
    for _, stream in native_assembly_streams(output, manifest):seen.update(check_stream(graph, stream))
    wanted = collections.Counter((o['site'], note(c, o)) for c in graph['joined_reference_contexts'] for o in c['observations'])
    assert seen == wanted, 'Joined-reference comments differ across authoritative output files'
    return sum(seen.values())
