"""Join already checked field reads and role-backed input proofs, without field typing."""
import collections
import re
from async_field_accesses import quote

FIELDS = ('async_field_input_links', 'async_field_input_work')
SCOPE = 'conditional_loaded_word_only'
LIMIT, LINK_LIMIT = 200000, 4096


def role_proven(graph, origin, edges, shapes, contracts, asyncs):
    if not graph['call_input_abi']['supported'] or graph['call_input_abi']['word_bytes'] != 8:
        return False
    e = edges.get(origin['site'])
    if not e or e['source'] != origin['payload'] or e.get('target') is None:
        return False
    if origin['index'] is not None:
        s = shapes.get(origin['site'])
        return (origin['role'] == 'supplied_input' and origin['register'] is None and
            origin['sp_offset'] is not None and e['kind'] == 'call' and s is not None and
            s['payload'] == origin['payload'] and s['target'] == e['target'] and
            0 <= origin['index'] < s['count'] and
            origin['sp_offset'] == (s['count'] - origin['index'] - 1) * s['word_bytes'])
    reg = origin['register']
    if type(reg) is not int or not 0 <= reg < 15 or origin['sp_offset'] is not None:
        return False
    if e['kind'] == 'call' and e['target'] in contracts:
        if any(i['register'] == 'x' + str(reg) and i['role'] == origin['role'] for i in contracts[e['target']]['inputs']):
            return True
    op = asyncs.get(e['target'])
    return reg == 0 and ((origin['role'] == 'await_input' and e['kind'] == 'call' and op in ('await', 'await_with_type_check')) or
        (origin['role'] == 'completion_operand' and e['kind'] == 'jump' and op in ('complete_value', 'complete_value_or_future')))


def matches(context, access, layout, origin):
    if access['access'] != 'read' or origin['payload'] != context['payload'] or not origin['chain'] or origin['condition'] != 'normal_fallthrough':
        return False
    step = origin['chain'][0]
    v = step['source']
    if step['relation'] != 'input' or step['stop'] != 'load_endpoint' or step['pool_index'] is not None or not v:
        return False
    if v['kind'] not in ('load', 'load_compressed') or not v['load']:
        return False
    l, proof = v['load'], v['proof']
    return (v['site'] == access['site'] and l['base'] == access['base'] and
        0 <= l['displacement'] <= 1048576 and l['displacement'] + layout['tag'] == access['offset'] and
        l['bytes'] == access['bytes'] == layout['slot_bytes'] == (4 if v['kind'] == 'load_compressed' else 8) and
        2 <= len(proof) <= 65 and 0 < origin['site'] - access['site'] <= 256 and
        proof == list(range(access['site'], origin['site'] + 4, 4)) and
        step['steps'] == len(proof) - 1 and 0 <= access['site'] - context['seed'] < context['steps'] * 4 and
        context['steps'] <= 64)


def expected(graph):
    work = dict(limit=LIMIT, link_limit=LINK_LIMIT, origins_examined=0, candidates=0, remaining=LIMIT, complete=True)
    if not graph['async_field_work']['supported']:
        return [], work
    fields = graph['async_field_contexts']
    layouts = {l['class_id']: l for l in graph['async_field_layouts']}
    by_load = collections.defaultdict(list)
    for n, c in enumerate(fields):
        for m, a in enumerate(c['accesses']):
            if a['access'] == 'read':
                by_load[c['payload'], a['site']].append((n, m))
    links = []
    if not by_load:
        return links, work
    origins = graph['call_input_origins']
    edges = {e['site']: e for e in graph['edges']}
    shapes = {s['site']: s for s in graph['call_input_shapes']}
    contracts = {s['entry']: s for s in graph['stub_input_contracts']}
    asyncs = {s['entry']: s['operation'] for s in graph['async_contracts']}
    work['origins_examined'] = len(origins)
    for n, origin in enumerate(origins):
        first = origin['chain'][0]['source'] if origin['chain'] else None
        rows = by_load.get((origin['payload'], first['site'])) if first else None
        if not rows or not role_proven(graph, origin, edges, shapes, contracts, asyncs):
            continue
        for context, access in rows:
            if work['remaining'] == 0 or len(links) == LINK_LIMIT:
                work['complete'] = False
                return links, work
            work['candidates'] += 1
            work['remaining'] -= 1
            c = fields[context]
            if matches(c, c['accesses'][access], layouts[c['class_id']], origin):
                links.append(dict(context=context, access=access, input_origin=n, scope=SCOPE))
    return links, work


def check_field_inputs(graph):
    if graph.get('format', 0) < 41:
        return 0
    links, work = expected(graph)
    assert graph['async_field_input_links'] == links, 'Field input lacks its direct load, role or conditional owner'
    assert graph['async_field_input_work'] == work, 'Field input work accounting differs'
    return len(links)


def note(graph, link, class_names=None):
    c = graph['async_field_contexts'][link['context']]
    a = c['accesses'][link['access']]
    o = graph['call_input_origins'][link['input_origin']]
    layout = next(l for l in graph['async_field_layouts'] if l['class_id'] == c['class_id'])
    if o['index'] is not None:
        label = f"supplied input[{o['index']}] (SP+{o['sp_offset']:#x})"
    else:
        role = 'async completion operand' if o['role'] == 'completion_operand' else o['role'].replace('_', ' ')
        label = f"{role} (X{o['register']})"
    owner = f"class {c['class_id']:#x}"
    if class_names is not None and c['class_id'] in class_names:
        owner += ' (' + quote(class_names[c['class_id']]) + ')'
    storage = 'context parent' if a['kind'] == 'context_parent' else f"context slot {a['index']} (bounds unknown)" if a['kind'] == 'context_slot' else 'instance slot'
    for f in layout['fields']:
        if f['offset'] == a['offset']:
            storage = 'field ' + quote(f['name'])
    return (f"field input origin: {label} <- {storage} at byte {a['offset']:#x} of {owner}; read {a['site']:#x} "
        f"[conditional: {c['basis']} seed {c['seed']:#x}; delivery at await {c['source_await']:#x}; "
        'normal producer/call returns; successful SDK resumes; value/error-preserving callbacks; copied loaded word only; field value/type unknown]')


def check_stream(graph, stream, class_names=None):
    expected_notes = collections.defaultdict(list)
    for link in graph.get('async_field_input_links', []):
        assert link['scope'] == SCOPE, 'Field input scope was lost'
        expected_notes[graph['call_input_origins'][link['input_origin']]['site']].append(note(graph, link, class_names))
    pending = []
    seen = collections.Counter()
    for line in stream:
        if 'field input origin:' in line:
            assert re.match(r'^\s*// field input origin:', line), 'Malformed field input comment'
            text = line.strip()[3:]
            if class_names is not None:
                owner = re.search(r'class (0x[0-9a-f]+) \(("(?:[^"\\]|\\.)*")\)', text)
                if owner and int(owner[1], 16) not in class_names:
                    text = text[:owner.start(2) - 2] + text[owner.end(2) + 1:]
            pending.append(text)
        m = re.match(r'^\s*// (0x[0-9a-f]+):', line)
        if m:
            pc = int(m[1], 16)
            wanted = collections.Counter(expected_notes[pc])
            assert collections.Counter(pending) == wanted, 'Missing, duplicate or misplaced field input comment'
            seen.update((pc, text) for text in pending)
            assert all(seen[pc, text] == count for text, count in wanted.items()), 'Repeated field input instruction'
            pending = []
    assert not pending, 'Unattached field input comment'
    return seen


def check_output(graph, output):
    import json
    from native_assembly import native_assembly_streams
    from check_call_result_notes import metadata_class_names
    names = metadata_class_names((output / 'blutter_frida.js').read_text())
    manifest = json.loads((output / 'snapshot_code.json').read_text())
    seen = collections.Counter()
    for _, stream in native_assembly_streams(output, manifest):
        seen.update(check_stream(graph, stream, names))
    wanted = collections.Counter((graph['call_input_origins'][l['input_origin']]['site'], note(graph, l, names))
        for l in graph.get('async_field_input_links', []))
    assert seen == wanted, 'Field input comments differ across output files'
    return sum(seen.values())
