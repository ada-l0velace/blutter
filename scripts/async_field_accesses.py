"""Check conditional storage identities; no heap-value or alias preservation claim."""
import collections
import json
import re
from async_future_bindings import CONDITIONS

FIELDS = ('async_field_layouts', 'async_field_contexts', 'async_field_work')
SCOPE = 'conditional_layout_only'


def seeds(graph):
    result = []
    bindings = {b['site']: b for b in graph.get('await_future_bindings', [])}
    for b in graph.get('await_future_bindings', []):
        if b['status'] == 'conditional_delivery' and b['value'] == 'heap_class' and b.get('resume_site'):
            assert b['conditions'] == CONDITIONS, 'Field seed lost its delivery conditions'
            result.append((b['payload'], b['site'], b['resume_site'], 0, b['class_id'], 'await_delivery'))
    for c in graph.get('saved_reference_contexts', []):
        if c['status'] == 'checked' and c['class_id'] != graph['receiver_metadata']['null_class_id']:
            b = bindings[c['source_await']]
            assert c['scope'] == 'conditional_saved_reference_only' and b['status'] == 'conditional_delivery' and b['value'] == 'heap_class' and b['class_id'] == c['class_id'] and b['conditions'] == CONDITIONS, 'Field seed lost its saved-reference source'
            for o in c['observations']:
                result.append((c['payload'], c['source_await'], o['site'] + 4, o['register'], c['class_id'], 'restored_reference'))
    return result


def context_key(c):
    return tuple(c[k] for k in ('payload', 'source_await', 'seed', 'register', 'class_id', 'basis'))


def expected_layout(cid, audit):
    tag, width, header, context_cid, parent, data = audit['instance_field_abi']
    if tag != 1 or width != 4:
        return dict(class_id=cid, kind='unsupported', header=0, end=0, tag=0,
            slot_bytes=0, context_parent=0, context_data=0, excluded=[], unboxed=[], fields=[])
    l = dict(class_id=cid, kind='unsupported', header=header, end=0, tag=tag,
             slot_bytes=width, context_parent=0, context_data=0, excluded=[], unboxed=[], fields=[])
    if cid == context_cid:
        l.update(kind='context', end=data, context_parent=parent, context_data=data)
        return l
    classes = {r[0]: r for r in audit['instance_field_metadata']}
    if cid not in classes:
        return l
    _, end, _, bitmap, _, _ = classes[cid]
    if end < header or end > 1048576:
        l['end'] = end
        return l
    l.update(kind='instance', end=end, unboxed=[off for off in range(header, end, width) if bitmap >> (off // width) & 1])
    owner = cid
    visited = set()
    while owner in classes:
        assert owner not in visited, 'Cyclic field owner metadata'
        visited.add(owner)
        _, _, type_args, _, parent, fields = classes[owner]
        if header <= type_args < end:
            l['excluded'].append(type_args)
        l['fields'] += [dict(offset=offset, owner=owner, name=name, declared_type=typ) for offset, name, typ in fields]
        owner = parent
    l['excluded'] = sorted(set(l['excluded']))
    l['fields'].sort(key=lambda f: f['offset'])
    return l


def replay(insns, context, layout, barriers):
    """Architectural write-set replay intentionally admits more than native opaque IR."""
    import capstone as cs
    from capstone import arm64 as a
    active = {context['register']}
    observations = []
    insns = list(insns)
    def number(i, r):
        n = i.reg_name(r)
        return int(n[1:]) if n and n[0] in 'xw' and n[1:].isdigit() else -1
    for i in insns:
        if i.group(cs.CS_GRP_JUMP) and i.operands and i.operands[-1].type == a.ARM64_OP_IMM:
            barriers.add(i.operands[-1].imm)
    for i in insns:
        if i.address < context['seed']:
            continue
        if i.address in barriers:
            break
        if any(i.group(g) for g in (cs.CS_GRP_CALL, cs.CS_GRP_JUMP, cs.CS_GRP_RET, cs.CS_GRP_INT)) or i.id == a.ARM64_INS_BRK:
            break
        o = i.operands
        load = i.id in (a.ARM64_INS_LDR, a.ARM64_INS_LDUR, a.ARM64_INS_LDTR)
        store = i.id in (a.ARM64_INS_STR, a.ARM64_INS_STUR)
        if (load or store) and len(o) == 2 and not i.writeback and o[0].type == a.ARM64_OP_REG and o[1].type == a.ARM64_OP_MEM and not o[1].mem.index:
            base, reg = number(i, o[1].mem.base), number(i, o[0].reg)
            width = 4 if i.reg_name(o[0].reg).startswith('w') else 8 if i.reg_name(o[0].reg).startswith('x') else 0
            off = o[1].mem.disp + layout['tag']
            kind, index = '', None
            if base in active and width == layout['slot_bytes'] and 0 <= o[1].mem.disp < 1048576:
                if layout['kind'] == 'context':
                    if off == layout['context_parent']:
                        kind = 'context_parent'
                    elif off >= layout['context_data'] and (off - layout['context_data']) % width == 0:
                        kind, index = 'context_slot', (off - layout['context_data']) // width
                elif layout['kind'] == 'instance' and layout['header'] <= off and off + width <= layout['end'] and off % width == 0 and off not in layout['excluded'] + layout['unboxed']:
                    kind = 'instance_slot'
                if kind:
                    observations.append(dict(site=i.address, base=base, register=reg, bytes=width,
                        offset=off, access='read' if load else 'write', kind=kind, index=index))
        before = active.copy()
        writes = {number(i, r) for r in i.regs_write}
        writes.update(number(i, v.reg) for v in o if v.type == a.ARM64_OP_REG and v.access & cs.CS_AC_WRITE)
        if i.writeback:
            writes.update(number(i, v.mem.base) for v in o if v.type == a.ARM64_OP_MEM)
        active -= writes
        if i.id == a.ARM64_INS_MOV and len(o) == 2 and all(v.type == a.ARM64_OP_REG and i.reg_name(v.reg).startswith('x') for v in o) and number(i, o[1].reg) in before:
            active.add(number(i, o[0].reg))
        if not active:
            break
    return observations


def check_fields(graph, audit, read):
    if graph.get('format', 0) < 40:
        return 0
    import capstone as cs
    from check_snapshot_annotations import decode_payload
    contexts = graph['async_field_contexts']
    work = graph['async_field_work']
    if not work['supported']:
        assert not contexts and not graph['async_field_layouts'] and work['steps'] == 0 and work['remaining'] == 200000
        return 0
    assert [context_key(c) for c in contexts] == seeds(graph), 'Field contexts differ from their conditional sources'
    layouts = {l['class_id']: l for l in graph['async_field_layouts']}
    assert len(layouts) == len(graph['async_field_layouts']) and set(layouts) == {c['class_id'] for c in contexts}
    for cid, l in layouts.items():
        assert l == expected_layout(cid, audit), 'Field layout differs from typed VM metadata'
    assert work['limit'] == 200000 and work['local_limit'] == 64
    assert work['steps'] == sum(c['steps'] for c in contexts) and work['steps'] + work['remaining'] == 200000
    bodies = {b['payload']: b for b in graph['future_binding_bodies']}
    md = cs.Cs(cs.CS_ARCH_ARM64, cs.CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    decoded = {}
    checked = 0
    for c in contexts:
        assert c['scope'] == SCOPE and 0 <= c['steps'] <= 64
        assert c['status'] in ('unsupported_layout', 'missing_caller_bytes', 'missing_seed', 'payload_end',
            'alternate_entry', 'local_limit', 'work_limit', 'call_boundary', 'control_boundary', 'registers_lost')
        if not c['accesses']:
            continue
        assert c['status'] not in ('unsupported_layout', 'missing_caller_bytes', 'missing_seed')
        payload = c['payload']
        if payload not in decoded:
            decoded[payload] = list(decode_payload(md, read(payload, bodies[payload]['end'] - payload), payload))
        barriers = set(graph['receiver_metadata']['entries']) | set(bodies[payload]['handlers'])
        allowed = replay(decoded[payload], c, layouts[c['class_id']], barriers)
        assert len({o['site'] for o in c['accesses']}) == len(c['accesses']), 'Duplicate field observation'
        for o in c['accesses']:
            assert o in allowed and 0 <= o['site'] - c['seed'] < c['steps'] * 4, 'Field access lacks an original-byte owner proof'
        checked += len(c['accesses'])
    return checked


def quote(text):
    return '"' + ''.join('\\' + ch if ch in '"\\' else f'\\u{ord(ch):04x}' if ord(ch) < 32 or ord(ch) == 127 else ch for ch in text) + '"'


def note(c, a, layout, class_names=None):
    owner = f"class {c['class_id']:#x}"
    if class_names is not None and c['class_id'] in class_names:
        owner += ' (' + quote(class_names[c['class_id']]) + ')'
    storage = 'context parent' if a['kind'] == 'context_parent' else f"context slot {a['index']} (bounds unknown)" if a['kind'] == 'context_slot' else 'instance slot'
    declaration = 'name/type metadata unavailable'
    for f in layout['fields']:
        if f['offset'] == a['offset']:
            storage, declaration = 'field ' + quote(f['name']), 'declared type ' + quote(f['declared_type']) + f"; declaring class {f['owner']:#x}"
    return (f"async field-access: {a['access']} {storage} at byte {a['offset']:#x} of X{a['base']} {owner}; {declaration} "
        f"[conditional: {c['basis']} seed {c['seed']:#x}; delivery at await {c['source_await']:#x}; "
        'successful SDK resumes; value/error-preserving callbacks; layout only; field value unknown]')


def check_stream(graph, stream, class_names=None):
    layouts = {l['class_id']: l for l in graph.get('async_field_layouts', [])}
    expected = collections.defaultdict(list)
    for c in graph.get('async_field_contexts', []):
        assert c['scope'] == SCOPE, 'Field comment lost its conditional scope'
        for a in c['accesses']:
            expected[a['site']].append(note(c, a, layouts[c['class_id']], class_names))
    seen = collections.Counter()
    pending = []
    for line in stream:
        if 'async field-access:' in line:
            assert re.match(r'^\s*// async field-access:', line), 'Malformed field comment'
            text = line.strip()[3:]
            if class_names is not None:
                owner = re.search(r'class (0x[0-9a-f]+) \(("(?:[^"\\]|\\.)*")\)', text)
                if owner and int(owner[1], 16) not in class_names:
                    text = text[:owner.start(2) - 2] + text[owner.end(2) + 1:]
            pending.append(text)
        m = re.match(r'^\s*// (0x[0-9a-f]+):', line)
        if m:
            pc = int(m[1], 16)
            assert collections.Counter(pending) == collections.Counter(expected[pc]), 'Missing, duplicate or misplaced field comment'
            seen.update((pc, text) for text in pending)
            assert all(seen[pc, text] == count for text, count in collections.Counter(expected[pc]).items()), 'Duplicate field instruction annotation'
            pending = []
    assert not pending, 'Unattached field comment'
    return seen


def check_output(graph, output):
    from native_assembly import native_assembly_streams
    from check_call_result_notes import metadata_class_names
    names = metadata_class_names((output / 'blutter_frida.js').read_text())
    manifest = json.loads((output / 'snapshot_code.json').read_text())
    seen = collections.Counter()
    for _, stream in native_assembly_streams(output, manifest):
        seen.update(check_stream(graph, stream, names))
    layouts = {l['class_id']: l for l in graph.get('async_field_layouts', [])}
    expected = collections.Counter((a['site'], note(c, a, layouts[c['class_id']], names))
        for c in graph.get('async_field_contexts', []) for a in c['accesses'])
    assert seen == expected, 'Missing or duplicate field annotation across output files'
    return sum(seen.values())
