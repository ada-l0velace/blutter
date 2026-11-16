"""Independently replay selected container contents along every admitted path."""
import collections
import re
from fresh_field_initializations import parents, validate_structure as validate_fresh
from field_input_origins import role_proven

FIELDS = ('fresh_content_allocators', 'fresh_content_contexts', 'fresh_content_work')
SCOPE = 'conditional_container_contents_at_transfer'
STATUSES = {'unknown', 'missing_caller_bytes', 'payload_end', 'step_limit', 'region_limit',
    'alternate_entry', 'container_lost', 'unknown_transfer', 'unproved_stack_lifetime',
    'divergent_transfers', 'unsupported_branch', 'container_escaped', 'unproved_store',
    'selected_storage_overwritten', 'unproved_alias_write', 'unknown_effects',
    'unproved_container_use', 'stack_changed', 'consumer_role_unproved', 'matched_container_input'}


def validate_structure(graph):
    validate_fresh(graph)
    work, contexts = graph['fresh_content_work'], graph['fresh_content_contexts']
    assert all(work[k] == v for k, v in dict(limit=200000, region_limit=128, context_limit=4096).items())
    assert type(work['complete']) is bool and len(contexts) <= 4096
    assert work['steps'] == sum(c['steps'] for c in contexts) and work['steps'] + work['remaining'] == 200000
    assert 0 <= work['remaining'] <= 200000
    seeds = sorted((parents(graph, f)[0]['payload'], n) for n, f in enumerate(graph['fresh_field_contexts']) if f['write'])
    assert [c['initialization'] for c in contexts] == [n for _, n in seeds[:len(contexts)]]
    assert len(contexts) == len(seeds) or not work['complete']
    assert graph['fresh_content_allocators'] == sorted(set(graph['fresh_content_allocators']))
    for c in contexts:
        assert c['scope'] == SCOPE and c['status'] in STATUSES
        assert type(c['steps']) is int and 0 <= c['steps'] <= 128
        assert c['proof'] == sorted(set(c['proof']))
        f = graph['fresh_field_contexts'][c['initialization']]
        field, _, _ = parents(graph, f)
        if c['status'] == 'missing_caller_bytes':assert c['steps'] == 0 and not c['proof']
        else:
            assert len(c['proof']) == c['steps'] + 1 and c['proof'][0] == f['write']['site']
            assert all(type(pc) is int and pc % 4 == 0 and pc >= f['write']['site'] for pc in c['proof'])
        assert bool(c['inputs']) == (c['status'] == 'matched_container_input')
        assert (c['transfer'] is not None) == (c['status'] in ('matched_container_input', 'consumer_role_unproved'))
        assert c['inputs'] == sorted(set(c['inputs']))
        if c['transfer'] is not None:assert c['proof'] and c['proof'][-1] == c['transfer']
        for n in c['inputs']:
            o = graph['call_input_origins'][n]
            assert o['payload'] == field['payload'] and o['site'] == c['transfer']
    return contexts


def replay(graph, c, insns, entries):
    """Enumerate paths; native code instead computes meets in forward PC order."""
    import capstone as cs
    from capstone import arm64 as a
    f = graph['fresh_field_contexts'][c['initialization']];w = f['write']
    by_pc = {i.address: i for i in insns};start = w['site'];end = insns[-1].address + 4
    def num(r):
        s = insns[0].reg_name(r)
        return int(s[1:]) if s.startswith(('w', 'x')) and s[1:].isdigit() else 29 if s == 'fp' else 30 if s == 'lr' else -1
    def width(r):
        s = insns[0].reg_name(r)
        return 8 if s.startswith('x') or s in ('fp', 'lr') else 4 if s.startswith('w') else 0
    seed = by_pc[start];s = seed.operands
    assert seed.id in (a.ARM64_INS_STR, a.ARM64_INS_STUR) and len(s) == 2 and not seed.writeback
    assert s[0].type == a.ARM64_OP_REG and s[1].type == a.ARM64_OP_MEM and not s[1].mem.index
    assert num(s[0].reg) == w['register'] and width(s[0].reg) == w['bytes']
    assert num(s[1].mem.base) == w['base'] and s[1].mem.disp + 1 == w['offset']
    allocations = dict(graph['receiver_metadata']['allocation_returns'])
    bounds = {k: (low, high) for k, low, high in graph['receiver_metadata']['allocation_body_bounds']}
    masks = dict(graph['receiver_metadata']['preserved_call_registers'])
    permitted = set(graph['fresh_content_allocators'])
    edges = {e['site']: e for e in graph['edges']}
    shapes = {s['site']: s for s in graph['call_input_shapes']}
    contracts = {s['entry']: s for s in graph['stub_input_contracts']}
    asyncs = {s['entry']: s['operation'] for s in graph['async_contracts']}
    origins = [(n, o) for n, o in enumerate(graph['call_input_origins']) if o['site'] == c['transfer']]
    layout = next((l for l in graph['fresh_field_layouts'] if l['class_id'] == f['class_id']), None)
    pending = [(start + 4, {w['base']}, {}, set(), set())];visited = {start};terminals = []
    path_steps = 0;states = set();locations = []
    while pending:
        pc, objects, auxiliaries, arguments, path = pending.pop()
        state_key = (pc, frozenset(objects), tuple(sorted(auxiliaries.items())), frozenset(arguments))
        if state_key in states:continue
        states.add(state_key)
        path_steps += 1
        assert path_steps <= 16384, 'Independent content path budget exceeded'
        assert pc in by_pc and pc not in entries and pc not in path and (objects or arguments)
        i = by_pc[pc];o = i.operands;visited.add(pc);path = path | {pc}
        assert len(path) <= 128
        def push(target):
            assert target > pc and target in by_pc
            pending.append((target, set(objects), dict(auxiliaries), set(arguments), path))
        is_jump = i.group(cs.CS_GRP_JUMP)
        is_call = i.group(cs.CS_GRP_CALL)
        if is_call or is_jump:
            assert o and o[-1].type == a.ARM64_OP_IMM
            target = o[-1].imm
            if i.id == a.ARM64_INS_BL and target in permitted:
                assert target in allocations and target in masks and target in bounds and not masks[target] & 1
                assert 0 <= bounds[target][0] < bounds[target][1] <= 1048576 and not arguments
                objects = {r for r in objects if masks[target] & 1 << r}
                auxiliaries = {r: v for r, v in auxiliaries.items() if masks[target] & 1 << r}
                auxiliaries[0] = target;push(pc + 4);continue
            unconditional = i.id == a.ARM64_INS_B and i.cc == a.ARM64_CC_INVALID
            if i.id == a.ARM64_INS_BL or unconditional and target not in by_pc:
                assert pc == c['transfer'], 'A path reaches a different first transfer'
                if pc in edges:
                    assert edges[pc]['target'] == target and edges[pc]['source'] == insns[0].address
                    assert edges[pc]['kind'] == ('call' if i.id == a.ARM64_INS_BL else 'jump')
                links = set()
                for n, origin in origins:
                    if role_proven(graph, origin, edges, shapes, contracts, asyncs) and (
                        origin['register'] in objects or origin['sp_offset'] in arguments):links.add(n)
                terminals.append(links);locations.append(set(arguments));continue
            push(target)
            if not unconditional:push(pc + 4)
            continue
        assert not i.group(cs.CS_GRP_RET) and not i.group(cs.CS_GRP_INT) and i.id != a.ARM64_INS_BRK
        if i.id == a.ARM64_INS_MOV and len(o) == 2 and not i.writeback and not i.update_flags and all(v.type == a.ARM64_OP_REG and width(v.reg) == 8 and 0 <= num(v.reg) < 15 for v in o):
            to, source = (num(v.reg) for v in o);is_object = source in objects;aux = auxiliaries.get(source)
            objects.discard(to);auxiliaries.pop(to, None)
            if is_object:objects.add(to)
            if aux:auxiliaries[to] = aux
            push(pc + 4);continue
        if i.id in (a.ARM64_INS_STR, a.ARM64_INS_STUR) and len(o) == 2 and not i.writeback and o[0].type == a.ARM64_OP_REG and o[1].type == a.ARM64_OP_MEM and not o[1].mem.index:
            source, base = num(o[0].reg), num(o[1].mem.base);off = o[1].mem.disp;size = width(o[0].reg)
            if base == 15 and graph['call_input_abi']['supported'] and graph['call_input_abi']['word_bytes'] == 8 and 0 <= off <= 4096 and size == 8 and off % 8 == 0:
                arguments.discard(off)
                if source in objects:arguments.add(off)
                push(pc + 4);continue
            assert source not in objects, 'Container escapes before transfer'
            if base in objects:
                assert 0 <= off <= 1048576 and size == w['bytes']
                begin = off + 1
                assert begin >= w['offset'] + w['bytes'] or begin + size <= w['offset'], 'Selected storage overwritten'
                if f['kind'] == 'array_element':
                    data = graph['receiver_metadata']['array_body_contract'][2] + 1
                    assert begin >= data and (begin - data) % size == 0 and (begin - data) // size < f['length']
                else:
                    assert layout['header'] <= begin and begin + size <= layout['end'] and begin % size == 0
                    assert begin not in layout['excluded'] and begin not in layout['unboxed']
            else:
                assert base in auxiliaries, 'Untracked write may alias the selected storage'
                low, high = bounds[auxiliaries[base]]
                assert low <= off <= 1048576 and off + size <= high
            push(pc + 4);continue
        if i.id in (a.ARM64_INS_NOP, a.ARM64_INS_CMP, a.ARM64_INS_CMN, a.ARM64_INS_TST):push(pc + 4);continue
        assert i.mnemonic in {'mov', 'movz', 'movn', 'movk', 'add', 'sub', 'ubfx', 'ubfiz', 'sbfx', 'sbfiz', 'sxtw', 'lsl', 'lsr', 'asr', 'ldr', 'ldur', 'ldtr'}, 'Unsupported content effect'
        assert not i.writeback
        if not any(v.type == a.ARM64_OP_MEM for v in o):
            assert not any(v.type == a.ARM64_OP_REG and v.access & cs.CS_AC_READ and num(v.reg) in objects for v in o)
        writes = {num(r) for r in i.regs_write}
        writes.update(num(v.reg) for v in o if v.type == a.ARM64_OP_REG and v.access & cs.CS_AC_WRITE)
        assert not writes.intersection({15, 29, 31})
        objects.difference_update(writes)
        auxiliaries = {r: v for r, v in auxiliaries.items() if r not in writes}
        push(pc + 4)
    assert terminals and visited == set(c['proof']), 'Content certificate omits or adds original instructions'
    for i in insns:
        if i.group(cs.CS_GRP_JUMP) and i.operands and i.operands[-1].type == a.ARM64_OP_IMM:
            target = i.operands[-1].imm
            assert target not in visited or target == start or i.address in visited, 'Unproved incoming branch'
    expected = set.intersection(*terminals)
    assert set(c['inputs']) == expected, 'Content input role or location is not proved on every path'
    return set.intersection(*locations)


def check_contents(graph, audit, read):
    if graph.get('format', 0) < 44:return 0
    import capstone as cs
    from check_snapshot_annotations import decode_payload
    contexts = validate_structure(graph)
    expected = set(audit.get('fresh_content_allocators', [])).intersection(dict(graph['receiver_metadata']['allocation_returns']))
    assert set(graph['fresh_content_allocators']) == expected, 'Unmatched content-preserving SDK allocator'
    masks = dict(graph['receiver_metadata']['preserved_call_registers'])
    typed_masks = dict(audit.get('preserved_call_registers', []))
    bounds = {entry: (low, high) for entry, low, high in graph['receiver_metadata']['allocation_body_bounds']}
    typed_bounds = {entry: (low, high) for entry, low, high in audit.get('allocation_body_bounds', [])}
    for entry in expected:
        assert entry in masks and masks[entry] == typed_masks.get(entry) and not masks[entry] & 1
        assert entry in bounds and bounds[entry] == typed_bounds.get(entry)
    nodes = {n['start']: n for n in graph['nodes']}
    bodies = {b['payload']: b for b in graph['future_binding_bodies']}
    decoder = cs.Cs(cs.CS_ARCH_ARM64, cs.CS_MODE_LITTLE_ENDIAN);decoder.detail = True
    decoded = {};total = 0
    for c in contexts:
        if c['transfer'] is None:continue
        f = graph['fresh_field_contexts'][c['initialization']];field, _, _ = parents(graph, f);payload = field['payload']
        if payload not in decoded:decoded[payload] = list(decode_payload(decoder, read(payload, nodes[payload]['end'] - payload), payload))
        entries = set(graph['receiver_metadata']['entries']) | set(bodies[payload]['handlers'])
        replay(graph, c, decoded[payload], entries);total += 1
    return total


def note(graph, c, n):
    assert n in c['inputs'] and c['status'] == 'matched_container_input'
    f = graph['fresh_field_contexts'][c['initialization']];field, access, _ = parents(graph, f);w = f['write'];o = graph['call_input_origins'][n]
    role = f"supplied input[{o['index']}]" if o['index'] is not None else o['role']
    storage = f"array element [{w['index']}]" if w['index'] is not None else f"instance slot {w['offset']:#x}"
    return (f"container input origin: {role} contains {storage} <- captured read {access['site']:#x}; initialization {w['site']:#x} "
        f"[conditional: {field['basis']} seed {field['seed']:#x}; delivery at await {field['source_await']:#x}; "
        'normal producer/allocation returns; successful SDK resumes; value/error-preserving callbacks; '
        'selected contents preserved to transfer; callee element/field use and value type unknown]')


def check_stream(graph, stream):
    expected = collections.defaultdict(list)
    for c in graph.get('fresh_content_contexts', []):
        for n in c['inputs']:expected[c['transfer']].append(note(graph, c, n))
    pending, seen = [], collections.Counter()
    for line in stream:
        if 'container input origin:' in line:
            assert re.match(r'^\s*// container input origin:', line);pending.append(line.strip()[3:])
        m = re.match(r'^\s*// (0x[0-9a-f]+):', line)
        if m:
            pc = int(m[1], 16);wanted = collections.Counter(expected[pc])
            assert collections.Counter(pending) == wanted, 'Missing, duplicate or misplaced container-input note'
            seen.update((pc, text) for text in pending)
            assert all(seen[pc, text] == count for text, count in wanted.items());pending = []
    assert not pending
    return seen


def check_output(graph, output):
    import json
    from native_assembly import native_assembly_streams
    validate_structure(graph)
    manifest = json.loads((output/'snapshot_code.json').read_text());seen = collections.Counter()
    for _, stream in native_assembly_streams(output, manifest):seen.update(check_stream(graph, stream))
    wanted = collections.Counter((c['transfer'], note(graph, c, n)) for c in graph['fresh_content_contexts'] for n in c['inputs'])
    assert seen == wanted, 'Container-input comments differ across output files'
    return sum(seen.values())
