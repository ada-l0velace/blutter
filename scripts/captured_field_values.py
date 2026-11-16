"""Validate saved captured values using original bytes and audited GC spill maps."""
import collections
import re

FIELDS = ('captured_field_contexts', 'captured_field_stack_maps', 'captured_field_work')
SCOPE = 'conditional_captured_value_only'
LIMIT, REGION, CONTEXTS, MAPS = 200000, 64, 4096, 4096
STATUSES = {'unknown', 'unproved_owned_frame', 'missing_caller_bytes', 'payload_end',
    'unproved_reconstruction', 'step_limit', 'region_limit', 'alternate_entry',
    'unproved_active_frame', 'control_boundary', 'second_call', 'unmatched_call',
    'no_saved_value', 'map_limit', 'untagged_saved_value', 'missing_stack_map'}


def validate_structure(graph):
    work = graph['captured_field_work']
    rows = graph['captured_field_contexts']
    maps = graph['captured_field_stack_maps']
    assert all(work[k] == v for k, v in dict(limit=LIMIT, region_limit=REGION,
        context_limit=CONTEXTS, map_limit=MAPS).items()), 'Captured value limits differ'
    assert type(work['complete']) is bool and type(work['steps']) is int
    assert 0 <= work['steps'] <= LIMIT and work['remaining'] + work['steps'] == LIMIT
    assert len(rows) <= CONTEXTS and len(maps) <= MAPS
    assert work['steps'] == sum(c['steps'] for c in rows), 'Captured value work differs'
    fields = graph['async_field_contexts']
    enabled = graph['async_field_work']['supported'] and graph['saved_reference_abi']['supported'] and graph['future_binding_abi']['supported']
    seeds = sorted((c['payload'], n, m) for n, c in enumerate(fields)
        for m, a in enumerate(c['accesses']) if a['access'] == 'read') if enabled else []
    assert [(c['context'], c['access']) for c in rows] == [(n, m) for _, n, m in seeds[:len(rows)]], 'Captured value seeds differ'
    assert len(rows) == len(seeds) or not work['complete'], 'Missing captured value context'
    assert [m['site'] for m in maps] == sorted({m['site'] for m in maps})
    frames = {f['payload']: f for f in graph['saved_reference_frames']}
    by_map = {m['site']: m for m in maps}
    allocations = dict(graph['receiver_metadata']['allocation_returns'])
    first = graph['saved_reference_abi']['first_local_offset']
    reserved = graph['future_binding_abi']['suspend_state_offset']
    for m in maps:
        assert type(m['available']) is bool and type(m['spill_slots']) is int and 0 <= m['spill_slots'] <= 8192
        assert m['register_slots'] is None or type(m['register_slots']) is int and 0 <= m['register_slots'] <= 16384 - m['spill_slots']
        assert m['objects'] == sorted(set(m['objects']))
        assert all(type(off) is int and off % 8 == 0 and -69632 <= off <= first and (first - off) // 8 < m['spill_slots'] for off in m['objects'])
        assert m['available'] or not m['spill_slots'] and not m['objects'] and m['register_slots'] is None
    for c in rows:
        assert c['scope'] == SCOPE and c['status'] in STATUSES and type(c['steps']) is int and 0 <= c['steps'] <= REGION
        f = fields[c['context']]
        frame = frames.get(f['payload'])
        if not frame or frame['status'] != 'matched_async_frame':
            assert c['status'] == 'unproved_owned_frame' and not c['reloads'] and c['steps'] == 0
        assert [r['site'] for r in c['reloads']] == sorted({r['site'] for r in c['reloads']})
        if c['reloads']:
            assert frame and frame['status'] == 'matched_async_frame'
            assert c['status'] not in {'unknown', 'unproved_owned_frame', 'missing_caller_bytes',
                'unproved_reconstruction', 'no_saved_value', 'missing_stack_map', 'untagged_saved_value'}
            points = {pc: (sp, exact) for pc, sp, exact in frame['points']}
            access = f['accesses'][c['access']]
            for r in c['reloads']:
                assert type(r['register']) is int and 0 <= r['register'] < 15
                assert access['site'] < r['store'] < r['call'] < r['site']
                assert r['site'] - access['site'] <= (c['steps'] + (2 if access['bytes'] == 4 else 1)) * 4
                off = r['slot']
                assert type(off) is int and -4096 <= off <= first and off % 8 == 0 and off + 8 <= reserved
                assert all(pc in points and off >= points[pc][0] for pc in (r['store'], r['call'], r['site']))
                m = by_map[r['call']]
                assert m['payload'] == f['payload'] and m['available'] and r['target'] in allocations
                assert off in m['objects'] or m['register_slots'] == 0 and off <= first - m['spill_slots'] * 8

    return rows


def replay(insns, access, points, barriers, maps, allocations, first, reserved, heap):
    """Architectural write sets over-approximate the native copy subset, without its IR."""
    import capstone as cs
    from capstone import arm64 as a
    def number(reg):
        name = insns[0].reg_name(reg)
        return 29 if name == 'fp' else 30 if name == 'lr' else int(name[1:]) if name.startswith(('x', 'w')) and name[1:].isdigit() else -1
    def width(reg):
        name = insns[0].reg_name(reg)
        return 16 if name.startswith('q') else 8 if name in ('fp', 'lr') or name.startswith(('x', 'd')) else 4 if name.startswith(('w', 's')) else 0
    def slot(off, point):
        return -4096 <= off <= first and off % 8 == 0 and off + 8 <= reserved and off >= point[0]
    idx = next(n for n, i in enumerate(insns) if i.address == access['site'])
    i = insns[idx]
    o = i.operands
    assert i.id in (a.ARM64_INS_LDR, a.ARM64_INS_LDUR) and len(o) == 2 and not i.writeback
    assert o[0].type == a.ARM64_OP_REG and number(o[0].reg) == access['register'] and width(o[0].reg) == access['bytes']
    assert o[1].type == a.ARM64_OP_MEM and number(o[1].mem.base) == access['base'] and not o[1].mem.index
    idx += 1
    if access['bytes'] == 4:
        if idx == len(insns):return []
        i = insns[idx]
        o = i.operands
        if i.address in barriers or i.id != a.ARM64_INS_ADD or len(o) != 3 or i.writeback or i.update_flags:
            return []
        if not all(x.type == a.ARM64_OP_REG for x in o) or width(o[0].reg) != 8 or number(o[0].reg) != access['register'] or o[1].reg != o[0].reg or i.reg_name(o[2].reg) != heap or o[2].ext or o[2].shift.type != a.ARM64_SFT_LSL or o[2].shift.value != 32:
            return []
        idx += 1
    regs = {access['register']}
    slots, observations = {}, []
    call = target = None
    stores = tuple(getattr(a, 'ARM64_INS_' + name) for name in ('STP', 'STR', 'STUR', 'STRB', 'STURB', 'STRH', 'STURH'))
    for i in insns[idx:idx + REGION]:
        pc, o = i.address, i.operands
        if pc in barriers or pc not in points:break
        point = points[pc]
        slots = {off: store for off, store in slots.items() if slot(off, point)}
        is_call = i.group(cs.CS_GRP_CALL)
        if (not is_call and i.group(cs.CS_GRP_JUMP)) or i.group(cs.CS_GRP_RET) or i.group(cs.CS_GRP_INT) or i.id == a.ARM64_INS_BRK:break
        if is_call:
            if call is not None or i.id != a.ARM64_INS_BL or len(o) != 1 or o[0].type != a.ARM64_OP_IMM or o[0].imm not in allocations or not slots:break
            m = maps.get(pc)
            slots = {off: store for off, store in slots.items() if m and m['available'] and (off in m['objects'] or m.get('register_slots') == 0 and off <= first - m['spill_slots'] * 8)}
            regs = set()
            if not slots:break
            call, target = pc, o[0].imm
        elif i.id in stores:
            mem = o[-1].mem
            base = number(mem.base)
            if base in (15, 29):
                size = 1 if i.id in (a.ARM64_INS_STRB, a.ARM64_INS_STURB) else 2 if i.id in (a.ARM64_INS_STRH, a.ARM64_INS_STURH) else width(o[0].reg)
                count = 2 if i.id == a.ARM64_INS_STP else 1
                if not size or mem.index or i.writeback and base != 15 or base == 15 and not point[1]:slots = {}
                else:
                    off = mem.disp + (point[0] if base == 15 else 0)
                    slots = {at: store for at, store in slots.items() if not off < at + 8 or not off + size * count > at}
                    if call is None:
                        for n in range(count):
                            at = off + n * size
                            if size == 8 and number(o[n].reg) in regs and slot(at, point):slots[at] = pc
            if i.writeback:regs.discard(base)
        elif i.id in (a.ARM64_INS_LDR, a.ARM64_INS_LDUR, a.ARM64_INS_LDTR) and len(o) == 2 and not i.writeback and o[0].type == a.ARM64_OP_REG and width(o[0].reg) == 8 and 0 <= number(o[0].reg) < 15 and o[1].type == a.ARM64_OP_MEM and o[1].mem.base == a.ARM64_REG_X29 and not o[1].mem.index:
            reg, off = number(o[0].reg), o[1].mem.disp
            regs.discard(reg)
            if off in slots:
                regs.add(reg)
                if call is not None:observations.append(dict(site=pc, register=reg, slot=off, store=slots[off], call=call, target=target))
        else:
            prior = set(regs)
            written = {number(r) for r in i.regs_write}
            written.update(number(v.reg) for v in o if v.type == a.ARM64_OP_REG and v.access & cs.CS_AC_WRITE)
            if i.writeback:written.update(number(v.mem.base) for v in o if v.type == a.ARM64_OP_MEM)
            regs.difference_update(written)
            if i.id == a.ARM64_INS_MOV and len(o) == 2 and all(v.type == a.ARM64_OP_REG for v in o) and width(o[0].reg) == width(o[1].reg) == 8 and 0 <= number(o[0].reg) < 15 and number(o[1].reg) in prior:regs.add(number(o[0].reg))
    return observations


def check_captures(graph, audit, read):
    if graph.get('format', 0) < 42:return 0
    import capstone as cs
    from check_snapshot_annotations import decode_payload
    rows = validate_structure(graph)
    maps = graph['captured_field_stack_maps']
    typed = {(m['payload'], m['site']): m for m in audit.get('saved_reference_stack_maps', [])} if audit else {}
    register_slots = dict(audit.get('captured_field_register_slots', [])) if audit else {}
    for m in maps:
        assert {k: v for k, v in m.items() if k != 'register_slots'} == typed.get((m['payload'], m['site'])), 'Captured-value spill map differs from VM audit'
        assert m.get('register_slots') == register_slots.get(m['site']), 'Captured-value GC map extent differs from VM audit'
    decoded = {}
    nodes = {n['start']: n for n in graph['nodes']}
    frames = {f['payload']: f for f in graph['saved_reference_frames']}
    bodies = {b['payload']: b for b in graph['future_binding_bodies']}
    allocations = dict(graph['receiver_metadata']['allocation_returns'])
    first = graph['saved_reference_abi']['first_local_offset']
    reserved = graph['future_binding_abi']['suspend_state_offset']
    decoder = cs.Cs(cs.CS_ARCH_ARM64, cs.CS_MODE_LITTLE_ENDIAN)
    decoder.detail = True
    total = 0
    for c in rows:
        field = graph['async_field_contexts'][c['context']]
        access = field['accesses'][c['access']]
        payload = field['payload']
        if not c['reloads']:continue
        if payload not in decoded:decoded[payload] = list(decode_payload(decoder, read(payload, nodes[payload]['end'] - payload), payload))
        insns = decoded[payload]
        barriers = set(graph['receiver_metadata']['entries']) | set(bodies[payload]['handlers'])
        for i in insns:
            if i.group(cs.CS_GRP_JUMP) and i.operands and i.operands[-1].type == cs.arm64.ARM64_OP_IMM:barriers.add(i.operands[-1].imm)
        allowed = replay(insns, access, {pc: (sp, exact) for pc, sp, exact in frames[payload]['points']}, barriers,
            {m['site']: m for m in maps}, allocations, first, reserved, graph['receiver_metadata']['heap_bits_register'])
        for r in c['reloads']:
            assert r in allowed, 'Captured-value reload lacks original-byte preservation proof'
            assert 0 < r['site'] - access['site'] <= (c['steps'] + (2 if access['bytes'] == 4 else 1)) * 4
        total += len(c['reloads'])
    return total


def note(graph, context, reload):
    c = graph['async_field_contexts'][context['context']]
    a = c['accesses'][context['access']]
    r = reload
    return (f"captured field value: X{r['register']} <- read {a['site']:#x} from class {c['class_id']:#x} slot {a['offset']:#x}; "
        f"store {r['store']:#x} to FP{r['slot']:+}; reload after allocator {r['target']:#x} at {r['call']:#x} "
        f"[conditional: {c['basis']} seed {c['seed']:#x}; delivery at await {c['source_await']:#x}; "
        'normal producer/allocation returns; successful SDK resumes; value/error-preserving callbacks; '
        'owned GC-tagged local; captured Dart value only; current field contents/type unknown]')


def check_stream(graph, stream):
    expected = collections.defaultdict(list)
    for c in graph.get('captured_field_contexts', []):
        assert c['scope'] == SCOPE
        for r in c['reloads']:expected[r['site']].append(note(graph, c, r))
    pending, seen = [], collections.Counter()
    for line in stream:
        if 'captured field value:' in line:
            assert re.match(r'^\s*// captured field value:', line), 'Malformed captured value comment'
            pending.append(line.strip()[3:])
        m = re.match(r'^\s*// (0x[0-9a-f]+):', line)
        if m:
            pc = int(m[1], 16)
            wanted = collections.Counter(expected[pc])
            assert collections.Counter(pending) == wanted, 'Missing, duplicate or misplaced captured value comment'
            seen.update((pc, text) for text in pending)
            assert all(seen[pc, text] == count for text, count in wanted.items()), 'Repeated captured value instruction'
            pending = []
    assert not pending, 'Unattached captured value comment'
    return seen


def check_output(graph, output):
    import json
    from native_assembly import native_assembly_streams
    manifest = json.loads((output / 'snapshot_code.json').read_text())
    seen = collections.Counter()
    for _, stream in native_assembly_streams(output, manifest):seen.update(check_stream(graph, stream))
    wanted = collections.Counter((r['site'], note(graph, c, r)) for c in graph.get('captured_field_contexts', []) for r in c['reloads'])
    assert seen == wanted, 'Captured-value comments differ across output files'
    return sum(seen.values())
