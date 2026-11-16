"""Check first caller writes to fresh storage, not persistent heap contents."""
import collections
import re

FIELDS = ('fresh_field_layouts', 'fresh_field_contexts', 'fresh_field_work')
SCOPE = 'conditional_first_write_only'
STATUSES = {'unknown', 'missing_caller_bytes', 'unproved_array_length', 'unproved_allocation_layout',
    'payload_end', 'step_limit', 'region_limit', 'alternate_entry', 'control_boundary', 'fresh_result_escaped',
    'unproved_destination', 'unproved_alias_write', 'previously_written', 'matched_initialization', 'unproved_fresh_use', 'unknown_effects'}


def parents(graph, context):
    capture = graph['captured_field_contexts'][context['capture']]
    reload = capture['reloads'][context['reload']]
    field = graph['async_field_contexts'][capture['context']]
    return field, field['accesses'][capture['access']], reload


def validate_structure(graph):
    from captured_field_values import validate_structure as validate_captures
    validate_captures(graph)
    contexts, work = graph['fresh_field_contexts'], graph['fresh_field_work']
    assert all(work[k] == v for k, v in dict(limit=200000, region_limit=64, context_limit=4096).items())
    assert type(work['complete']) is bool and len(contexts) <= 4096
    assert work['steps'] == sum(c['steps'] + c['length_steps'] for c in contexts)
    assert 0 <= work['steps'] <= 200000 and work['remaining'] + work['steps'] == 200000
    seeds = sorted((graph['async_field_contexts'][c['context']]['payload'], n, m)
        for n, c in enumerate(graph['captured_field_contexts']) for m, _ in enumerate(c['reloads']))
    if graph['receiver_metadata']['allocation_result_register'] != 'x0':seeds = []
    assert [(c['capture'], c['reload']) for c in contexts] == [(n, m) for _, n, m in seeds[:len(contexts)]]
    assert len(contexts) == len(seeds) or not work['complete']
    layouts = {l['class_id']: l for l in graph['fresh_field_layouts']}
    assert len(layouts) == len(graph['fresh_field_layouts']) and list(layouts) == sorted(layouts)
    allocations = dict(graph['receiver_metadata']['allocation_returns'])
    for c in contexts:
        assert c['scope'] == SCOPE and c['status'] in STATUSES
        assert type(c['steps']) is int and 0 <= c['steps'] <= 64 and type(c['length_steps']) is int and 0 <= c['length_steps'] <= 64
        field, access, reload = parents(graph, c)
        if c['status'] != 'missing_caller_bytes':assert c['class_id'] == allocations[reload['target']]
        assert (c['status'] == 'matched_initialization') == bool(c['write'])
        if c['write']:
            w = c['write']
            assert reload['call'] < reload['site'] < w['site'] <= reload['call'] + 4 * c['steps']
            assert all(type(w[k]) is int and 0 <= w[k] < 15 for k in ('base', 'register'))
            assert c['kind'] in ('instance_field', 'array_element') and w['bytes'] in (4, 8)
            if c['kind'] == 'array_element':
                contract = graph['receiver_metadata']['array_body_contract']
                assert len(contract) == 5 and contract[0] == reload['target'] and contract[3] == w['bytes'] and contract[4] == 1
                assert type(c['length']) is int and type(w['index']) is int and 0 <= w['index'] < c['length'] <= 1048576 and c['length_source']
                assert w['offset'] == contract[2] + 1 + w['index'] * w['bytes']
                source = c['length_source']
                assert source['bits'] == c['length'] << contract[4]
                assert source['proof'] == list(range(source['site'], reload['call'] + 4, 4)) and c['length_steps'] == len(source['proof']) - 1
            else:
                assert w['index'] is None and c['class_id'] in layouts and c['length'] is None and c['length_source'] is None
                layout = layouts[c['class_id']]
                assert layout['kind'] == 'instance' and w['bytes'] == layout['slot_bytes'] and layout['tag'] == 1
                assert layout['header'] <= w['offset'] and w['offset'] + w['bytes'] <= layout['end'] and w['offset'] % w['bytes'] == 0
                assert w['offset'] not in layout['excluded'] and w['offset'] not in layout['unboxed']
                bounds = {entry: (low, high) for entry, low, high in graph['receiver_metadata']['allocation_body_bounds']}
                assert reload['target'] in bounds
                low, high = bounds[reload['target']]
                assert 0 <= low <= layout['header'] - layout['tag'] and layout['end'] - layout['tag'] <= high <= 1048576

    return contexts


def length_proof(c, reload, by_pc, barriers, contract):
    from check_snapshot_annotations import constant_move
    import capstone as cs
    from capstone import arm64 as a
    v = c['length_source']
    assert v and v['bits'] == c['length'] << contract[4] and not v['bits'] & 1
    proof = v['proof']
    assert proof == list(range(v['site'], reload['call'] + 4, 4)) and 2 <= len(proof) <= 65
    assert c['length_steps'] == len(proof) - 1
    reg = contract[1]
    for pc in reversed(proof[:-1]):
        i = by_pc[pc]
        assert (pc not in barriers or pc == v['site']) and not any(i.group(g) for g in (cs.CS_GRP_CALL, cs.CS_GRP_JUMP, cs.CS_GRP_RET, cs.CS_GRP_INT))
        move = constant_move(int.from_bytes(i.bytes, 'little'))
        if move and move[1] == reg:
            assert move[2] == 64
            if move[0] == 'literal' or move[0] == 'copy' and move[3] == 31:
                assert pc == v['site'] and v['bits'] == (move[3] if move[0] == 'literal' else 0)
                return
            assert move[0] == 'copy'
            reg = move[3]
        else:
            writes = set(i.regs_write) | {o.reg for o in i.operands if o.type == a.ARM64_OP_REG and o.access & cs.CS_AC_WRITE}
            if i.writeback:writes.update(o.mem.base for o in i.operands if o.type == a.ARM64_OP_MEM)
            assert all(i.reg_name(r) not in (f'x{reg}', f'w{reg}') for r in writes), 'Array length source overwritten'
    raise AssertionError('Array length lacks a literal definition')


def replay(insns, reload, barriers, layout, array, length):
    import capstone as cs
    from capstone import arm64 as a
    def num(r):
        s = insns[0].reg_name(r)
        return int(s[1:]) if s.startswith(('w', 'x')) and s[1:].isdigit() else -1
    def width(r):
        s = insns[0].reg_name(r)
        return 8 if s.startswith('x') or s in ('fp', 'lr') else 4 if s.startswith('w') else 0
    fresh, value, written = {0}, set(), set()
    start = next(n for n, i in enumerate(insns) if i.address == reload['call']) + 1
    loaded = False
    for i in insns[start:start + 64]:
        pc, o = i.address, i.operands
        if pc in barriers or any(i.group(g) for g in (cs.CS_GRP_CALL, cs.CS_GRP_JUMP, cs.CS_GRP_RET, cs.CS_GRP_INT)) or i.id == a.ARM64_INS_BRK:return None
        if pc == reload['site']:
            assert i.id in (a.ARM64_INS_LDR, a.ARM64_INS_LDUR, a.ARM64_INS_LDTR) and len(o) == 2 and not i.writeback
            assert o[0].type == a.ARM64_OP_REG and num(o[0].reg) == reload['register'] and width(o[0].reg) == 8
            assert o[1].type == a.ARM64_OP_MEM and o[1].mem.base == a.ARM64_REG_X29 and not o[1].mem.index and o[1].mem.disp == reload['slot']
            fresh.discard(reload['register']);value.add(reload['register']);loaded = True
            continue
        if i.id == a.ARM64_INS_MOV and len(o) == 2 and not i.writeback and not i.update_flags and all(v.type == a.ARM64_OP_REG and width(v.reg) == 8 and 0 <= num(v.reg) < 15 for v in o):
            to, source = (num(v.reg) for v in o)
            f, v = source in fresh, source in value
            fresh.discard(to);value.discard(to)
            if f:fresh.add(to)
            if v:value.add(to)
            continue
        if i.id in (a.ARM64_INS_STR, a.ARM64_INS_STUR) and len(o) == 2 and not i.writeback and o[0].type == a.ARM64_OP_REG and o[1].type == a.ARM64_OP_MEM and not o[1].mem.index:
            source, base = num(o[0].reg), num(o[1].mem.base)
            if source in fresh:return None
            if base in fresh:
                size = array[3] if array else layout['slot_bytes']
                off = o[1].mem.disp + (1 if array else layout['tag'])
                if width(o[0].reg) != size or not 0 <= o[1].mem.disp <= 1048576:return None
                index = None
                if array:
                    if off < array[2] + 1 or (off - array[2] - 1) % size:return None
                    index = (off - array[2] - 1) // size
                    if index >= length:return None
                elif off < layout['header'] or off + size > layout['end'] or off % size or off in layout['excluded'] or off in layout['unboxed']:return None
                if loaded and source in value:
                    return None if off in written else dict(site=pc, base=base, register=source, bytes=size, offset=off, index=index)
                written.add(off)
            else:return None
            continue
        for op in o:
            if op.type == a.ARM64_OP_REG and op.access & cs.CS_AC_READ and num(op.reg) in fresh:return None
            if op.type == a.ARM64_OP_MEM and any(num(r) in fresh for r in (op.mem.base, op.mem.index)):return None
        writes = {num(r) for r in i.regs_write}
        writes.update(num(op.reg) for op in o if op.type == a.ARM64_OP_REG and op.access & cs.CS_AC_WRITE)
        if i.writeback:writes.update(num(op.mem.base) for op in o if op.type == a.ARM64_OP_MEM)
        fresh.difference_update(writes);value.difference_update(writes)
    return None


def check_fresh_fields(graph, audit, read):
    if graph.get('format', 0) < 43:return 0
    import capstone as cs
    from check_snapshot_annotations import decode_payload
    from async_field_accesses import expected_layout
    contexts = validate_structure(graph)
    layouts = {l['class_id']: l for l in graph['fresh_field_layouts']}
    for cid, layout in layouts.items():
        if layout['kind'] == 'unsupported':assert not any(c['class_id'] == cid and c['write'] for c in contexts)
        else:assert audit and layout == expected_layout(cid, audit), 'Fresh destination layout differs from typed audit'
    nodes = {n['start']: n for n in graph['nodes']}
    bodies = {b['payload']: b for b in graph['future_binding_bodies']}
    bounds = {entry: (start, end) for entry, start, end in graph['receiver_metadata']['allocation_body_bounds']}
    contract = graph['receiver_metadata']['array_body_contract']
    decoder = cs.Cs(cs.CS_ARCH_ARM64, cs.CS_MODE_LITTLE_ENDIAN);decoder.detail = True
    decoded = {};total = 0
    for c in contexts:
        if not c['write']:continue
        f, a, reload = parents(graph, c);payload = f['payload']
        if payload not in decoded:decoded[payload] = list(decode_payload(decoder, read(payload, nodes[payload]['end'] - payload), payload))
        insns = decoded[payload];by_pc = {i.address: i for i in insns}
        call = by_pc[reload['call']]
        assert call.id == cs.arm64.ARM64_INS_BL and call.operands[0].imm == reload['target']
        barriers = set(graph['receiver_metadata']['entries']) | set(bodies[payload]['handlers'])
        for i in insns:
            if i.group(cs.CS_GRP_JUMP) and i.operands and i.operands[-1].type == cs.arm64.ARM64_OP_IMM:barriers.add(i.operands[-1].imm)
        layout = None;array = None
        if c['kind'] == 'array_element':
            assert len(contract) == 5 and contract[0] == reload['target'] and contract[4] == 1
            length_proof(c, reload, by_pc, barriers, contract);array = contract
        else:
            layout = layouts[c['class_id']]
            assert layout['kind'] == 'instance' and reload['target'] in bounds
            low, high = bounds[reload['target']]
            assert low <= layout['header'] - layout['tag'] and high >= layout['end'] - layout['tag']
        assert c['write'] == replay(insns, reload, barriers, layout, array, c['length']), 'Fresh write lacks original-byte value/allocation proof'
        total += 1
    return total


def note(graph, context):
    field, access, reload = parents(graph, context)
    w = context['write']
    destination = f"array element [{w['index']}]" if w['index'] is not None else f"instance slot {w['offset']:#x}"
    return (f"fresh initialization: {destination} of class {context['class_id']:#x} allocated at {reload['call']:#x} "
        f"<- read {access['site']:#x} from class {field['class_id']:#x} slot {access['offset']:#x}; reload {reload['site']:#x} "
        f"[conditional: {field['basis']} seed {field['seed']:#x}; delivery at await {field['source_await']:#x}; "
        'normal producer/allocation returns; successful SDK resumes; value/error-preserving callbacks; captured Dart value; '
        'unescaped allocation; first explicit write only; later contents/type unknown]')


def check_stream(graph, stream):
    expected = collections.defaultdict(list)
    for c in graph.get('fresh_field_contexts', []):
        assert c['scope'] == SCOPE
        if c['write']:expected[c['write']['site']].append(note(graph, c))
    pending, seen = [], collections.Counter()
    for line in stream:
        if 'fresh initialization:' in line:
            assert re.match(r'^\s*// fresh initialization:', line)
            pending.append(line.strip()[3:])
        m = re.match(r'^\s*// (0x[0-9a-f]+):', line)
        if m:
            pc = int(m[1], 16);wanted = collections.Counter(expected[pc])
            assert collections.Counter(pending) == wanted, 'Missing, duplicate or misplaced fresh initialization comment'
            seen.update((pc, text) for text in pending)
            assert all(seen[pc, text] == count for text, count in wanted.items())
            pending = []
    assert not pending
    return seen


def check_output(graph, output):
    import json
    from native_assembly import native_assembly_streams
    manifest = json.loads((output / 'snapshot_code.json').read_text());seen = collections.Counter()
    for _, stream in native_assembly_streams(output, manifest):seen.update(check_stream(graph, stream))
    wanted = collections.Counter((c['write']['site'], note(graph, c)) for c in graph.get('fresh_field_contexts', []) if c['write'])
    assert seen == wanted, 'Fresh initialization comments differ across output files'
    return sum(seen.values())
