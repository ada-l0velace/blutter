"""Check physical callee-entry reads independently against original machine bytes."""
import collections
import re
from fresh_content_uses import validate_structure as validate_contents, replay as replay_contents
from fresh_field_initializations import parents

FIELDS = ('callee_entry_read_contracts', 'container_entry_read_links', 'callee_entry_read_work')
LIMITS = dict(limit=200000, prefix_limit=64, body_limit=65536, byte_limit=4194304,
              contract_limit=4096, link_limit=4096, read_limit=16)
STOPS = {'unknown', 'unsupported_abi', 'step_limit', 'prefix_limit', 'read_limit',
         'body_end', 'call_or_return', 'unproved_control', 'unproved_store',
         'incoming_or_unowned_write', 'unproved_load', 'frame_register_load',
         'coordinate_lost', 'unknown_effects', 'body_limit', 'byte_limit', 'missing_bytes'}


def validate_structure(graph):
    validate_contents(graph)
    work = graph['callee_entry_read_work'];contracts = graph['callee_entry_read_contracts']
    links = graph['container_entry_read_links'];nodes = {n['start']: n['end'] for n in graph['nodes']}
    assert all(work[k] == v for k, v in LIMITS.items()) and type(work['complete']) is bool
    assert len(contracts) <= 4096 and len(links) <= 4096
    assert len({c['entry'] for c in contracts}) == len(contracts)
    assert work['steps'] == sum(c['decoded'] + c['steps'] for c in contracts)
    assert 0 <= work['remaining'] <= 200000 and work['remaining'] + work['steps'] == 200000
    assert work['bytes'] == sum(c['decoded'] * 4 for c in contracts) <= 4194304
    for c in contracts:
        assert type(c['entry']) is int and c['entry'] in nodes and c['end'] == nodes[c['entry']]
        assert c['entry'] % 4 == c['end'] % 4 == 0 and c['end'] > c['entry'] and c['stop'] in STOPS
        assert type(c['steps']) is int and 0 <= c['steps'] <= 64
        assert len(c['prefix']) <= c['steps'] <= len(c['prefix']) + 1
        assert c['prefix'] == list(range(c['entry'], c['entry'] + len(c['prefix']) * 4, 4))
        assert not c['decoded'] or c['decoded'] * 4 == c['end'] - c['entry'] <= 65536
        assert c['decoded'] or not (c['prefix'] or c['reads'] or c['guard'])
        assert len(c['reads']) <= 16
        assert c['reads'] == sorted(c['reads'], key=lambda r: (r['site'], r['part']))
        assert len({(r['site'], r['part']) for r in c['reads']}) == len(c['reads'])
        for r in c['reads']:
            assert r['site'] in c['prefix'] and r['bytes'] == 8
            assert type(r['register']) is int and 0 <= r['register'] < 15
            assert type(r['entry_sp_offset']) is int and 0 <= r['entry_sp_offset'] <= 248 and r['entry_sp_offset'] % 8 == 0
            assert r['part'] in (0, 1)
        if c['stop'] == 'step_limit':assert not c['reads'] and not work['complete']
    assert len({(l['context'], l['contract'], l['read']) for l in links}) == len(links)
    for l in links:
        assert l['scope'] == 'conditional_callee_entry_read'
        assert type(l['context']) is int and 0 <= l['context'] < len(graph['fresh_content_contexts'])
        assert type(l['contract']) is int and 0 <= l['contract'] < len(contracts)
        assert type(l['read']) is int and 0 <= l['read'] < len(contracts[l['contract']]['reads'])
        c = graph['fresh_content_contexts'][l['context']]
        assert c['transfer'] is not None and not c['inputs']
        edge = next(e for e in graph['edges'] if e['site'] == c['transfer'])
        assert edge['kind'] == 'call' and edge['target'] == contracts[l['contract']]['entry']
    return contracts, links


def replay_prefix(contract, insns, graph, audit):
    """Track entry-SP coordinates; every admitted store must be below entry SP."""
    import capstone as cs
    from capstone import arm64 as a
    from check_stack_checks import check_initial_stack_check
    assert insns and [i.address for i in insns] == list(range(contract['entry'], contract['end'], 4))
    assert len(insns) == contract['decoded']
    coordinates = {15: 0};reads = [];guard = contract['guard']
    if guard:
        condition = dict(guard, edge='fallthrough')
        check_initial_stack_check(dict(payload=contract['entry'], scope='entry_prefix',
            path_condition=condition), insns, graph, audit, set())
        assert guard['site'] in contract['prefix']
    def number(reg):
        name = insns[0].reg_name(reg)
        if name in ('fp', 'lr', 'sp'):return {'fp': 29, 'lr': 30, 'sp': 31}[name]
        return int(name[1:]) if name.startswith(('w', 'x')) and name[1:].isdigit() else -1
    def width(reg):
        name = insns[0].reg_name(reg)
        return 8 if name.startswith('x') or name in ('fp', 'lr', 'sp') else 4 if name.startswith('w') else 0
    def at(base, displacement):
        v = coordinates.get(number(base))
        return v + displacement if v is not None and -65536 <= displacement <= 65536 and -65536 <= v + displacement <= 65536 else None
    arithmetic = {'mov', 'movz', 'movn', 'movk', 'add', 'sub', 'ubfx', 'ubfiz', 'sbfx', 'sbfiz', 'sxtw', 'lsl', 'lsr', 'asr'}
    for i in insns[:len(contract['prefix'])]:
        o = i.operands
        assert not i.group(cs.CS_GRP_CALL) and not i.group(cs.CS_GRP_RET) and not i.group(cs.CS_GRP_INT) and i.mnemonic not in ('brk', 'hlt')
        if i.group(cs.CS_GRP_JUMP):
            assert guard and i.address == guard['site'];continue
        pair = i.id in (a.ARM64_INS_STP, a.ARM64_INS_LDP)
        if i.id in (a.ARM64_INS_STR, a.ARM64_INS_STUR, a.ARM64_INS_STP, a.ARM64_INS_LDR, a.ARM64_INS_LDUR, a.ARM64_INS_LDTR, a.ARM64_INS_LDP):
            m = 2 if pair else 1
            assert len(o) == m + 1 and o[m].type == a.ARM64_OP_MEM and not o[m].mem.index
            assert all(v.type == a.ARM64_OP_REG for v in o[:m])
            w = width(o[0].reg);assert w in (4, 8) and all(width(v.reg) == w for v in o[:m])
            memory = o[m].mem;offsets = [at(memory.base, memory.disp + w * n) for n in range(m)]
            if i.id in (a.ARM64_INS_STR, a.ARM64_INS_STUR, a.ARM64_INS_STP):
                assert offsets[0] is not None and 15 in coordinates
                if i.writeback:
                    assert number(memory.base) == 15 and memory.disp < 0
                    assert all(number(v.reg) != 15 for v in o[:m])
                    coordinates[15] = offsets[0]
                assert coordinates[15] <= offsets[0] and offsets[0] + w * m <= 0, 'Store may overwrite incoming stack'
            else:
                assert not i.writeback and all(number(v.reg) not in (-1, 15, 29, 31) for v in o[:m])
                assert not pair or o[0].reg != o[1].reg
                for part in range(m):
                    r = number(o[part].reg);off = offsets[part]
                    if len(reads) < 16 and w == 8 and r < 15 and off is not None and 0 <= off <= 248 and off % 8 == 0:
                        reads.append(dict(site=i.address, entry_sp_offset=off, register=r, part=part, bytes=8))
                    coordinates.pop(r, None)
            continue
        if i.id in (a.ARM64_INS_NOP, a.ARM64_INS_CMP, a.ARM64_INS_CMN, a.ARM64_INS_TST):continue
        assert i.mnemonic in arithmetic and o and o[0].type == a.ARM64_OP_REG and not i.writeback
        to = number(o[0].reg);value = None
        if i.id == a.ARM64_INS_MOV and len(o) == 2 and o[1].type == a.ARM64_OP_REG and width(o[0].reg) == width(o[1].reg) == 8:
            value = coordinates.get(number(o[1].reg))
        elif i.id in (a.ARM64_INS_ADD, a.ARM64_INS_SUB) and len(o) == 3 and width(o[0].reg) == 8 and o[1].type == a.ARM64_OP_REG and width(o[1].reg) == 8 and o[2].type == a.ARM64_OP_IMM:
            assert not o[2].ext and o[2].shift.type in (a.ARM64_SFT_INVALID, a.ARM64_SFT_LSL)
            amount = o[2].imm << o[2].shift.value
            if 0 <= amount <= 65536:value = at(o[1].reg, amount if i.id == a.ARM64_INS_ADD else -amount)
        assert 0 <= to < 31 and (to != 15 or value is not None and value <= 0)
        coordinates.pop(to, None)
        if value is not None:coordinates[to] = value
    if contract['stop'] == 'step_limit':reads = []
    assert reads == contract['reads'], 'Entry-load certificate differs from original prefix'


def check_entry_reads(graph, audit, read):
    if graph.get('format', 0) < 45:return 0
    import capstone as cs
    from check_snapshot_annotations import decode_payload, branch
    contracts, links = validate_structure(graph)
    if contracts:
        expected = audit['call_input_abi']
        assert {k: graph['call_input_abi'][k] for k in expected} == expected
        assert graph['call_input_abi']['reason'] == 'verified_compiler_policy'
        assert graph['call_input_abi']['supported'] and graph['call_input_abi']['word_bytes'] == 8
    decoder = cs.Cs(cs.CS_ARCH_ARM64, cs.CS_MODE_LITTLE_ENDIAN);decoder.detail = True
    for c in contracts:
        if c['decoded']:
            replay_prefix(c, list(decode_payload(decoder, read(c['entry'], c['end'] - c['entry']), c['entry'])), graph, audit)
    decoded = {};locations = {};nodes = {n['start']: n for n in graph['nodes']}
    bodies = {b['payload']: b for b in graph['future_binding_bodies']}
    for l in links:
        n = l['context'];context = graph['fresh_content_contexts'][n]
        if n not in locations:
            fresh = graph['fresh_field_contexts'][context['initialization']];field, _, _ = parents(graph, fresh);payload = field['payload']
            if payload not in decoded:decoded[payload] = list(decode_payload(decoder, read(payload, nodes[payload]['end'] - payload), payload))
            entries = set(graph['receiver_metadata']['entries']) | set(bodies[payload]['handlers'])
            locations[n] = replay_contents(graph, context, decoded[payload], entries)
        c = contracts[l['contract']];r = c['reads'][l['read']]
        assert r['entry_sp_offset'] in locations[n], 'Container is not in the callee-read incoming stack word'
        word = int.from_bytes(read(context['transfer'], 4), 'little')
        assert word & 0xfc000000 == 0x94000000 and branch(word, context['transfer'])[1] == c['entry']
    return len(links)


def note(graph, link):
    context = graph['fresh_content_contexts'][link['context']];f = graph['fresh_field_contexts'][context['initialization']]
    field, access, _ = parents(graph, f);w = f['write'];contract = graph['callee_entry_read_contracts'][link['contract']];r = contract['reads'][link['read']]
    storage = f"array element [{w['index']}]" if w['index'] is not None else f"instance slot {w['offset']:#x}"
    return (f"container consumer: callee entry SP+{r['entry_sp_offset']:#x}, read {r['site']:#x} contains {storage} <- captured read {access['site']:#x}; initialization {w['site']:#x} "
        f"[conditional: {field['basis']} seed {field['seed']:#x}; delivery at await {field['source_await']:#x}; "
        'normal producer/allocation returns; successful SDK resumes; value/error-preserving callbacks; ' +
        ('callee initial stack-check fast path; ' if contract['guard'] else '') +
        'pure entry prefix; selected contents at this read only; source parameter position/type and later element/field use unknown]')


def check_stream(graph, stream):
    expected = collections.defaultdict(list)
    for l in graph.get('container_entry_read_links', []):expected[graph['fresh_content_contexts'][l['context']]['transfer']].append(note(graph, l))
    pending = [];seen = collections.Counter()
    for line in stream:
        if 'container consumer:' in line:
            assert re.match(r'^\s*// container consumer:', line);pending.append(line.strip()[3:])
        m = re.match(r'^\s*// (0x[0-9a-f]+):', line)
        if m:
            pc = int(m[1], 16);wanted = collections.Counter(expected[pc])
            assert collections.Counter(pending) == wanted, 'Missing, duplicate or misplaced container-consumer note'
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
    wanted = collections.Counter((graph['fresh_content_contexts'][l['context']]['transfer'], note(graph, l)) for l in graph['container_entry_read_links'])
    assert seen == wanted, 'Container-consumer comments differ across output files'
    return sum(seen.values())
