"""Supplied input order over checked call shapes; no new value inference."""
from collections import defaultdict
import bisect
import struct

FAMILIES = ('call_result_contexts', 'sdk_stub_producer_contexts', 'sdk_stub_caller_contexts')
FIELDS = ('call_input_abi', 'call_input_descriptors', 'call_input_models', 'call_input_shapes', 'call_input_rejections')


def _integer(value, low=0, high=(1 << 64)-1):
    return type(value) is int and low <= value <= high


def shapes(graph):
    if graph.get('format', 0) < 34:
        return {}
    abi = graph['call_input_abi']
    assert type(abi['supported']) is bool and isinstance(abi['reason'], str), 'Malformed input ABI'
    assert _integer(abi['descriptor_register'], 0, 30) and _integer(abi['word_bytes'], 0, 8), 'Invalid input ABI resources'
    descriptors, models, result = {}, {}, {}
    for d in graph['call_input_descriptors']:
        assert all(_integer(d[k]) for k in ('pool_index', 'type_arguments', 'count', 'size', 'positional')), 'Malformed numerical descriptor'
        assert 1 <= d['count'] <= 32 and d['count'] == d['size'] and 0 <= d['positional'] <= d['count'], 'Unsupported descriptor shape'
        named = d.get('named', [])
        assert len(named) == d['count']-d['positional'], 'Missing named positions'
        assert all(type(n['index']) is int and '\0' not in n['name'] for n in named), 'Malformed named input label'
        assert {n['index'] for n in named} == set(range(d['positional'], d['count'])), 'Invalid named positions'
        assert all(isinstance(n['name'], str) and 0 < len(n['name'].encode('utf-8')) <= 4096 for n in named), 'Invalid named labels'
        assert len({n['name'] for n in named}) == len(named), 'Duplicate named label' 
        assert d['pool_index'] not in descriptors, 'Duplicate numerical descriptor'
        descriptors[d['pool_index']] = d
    for m in graph['call_input_models']:
        assert _integer(m['entry'], 4) and m['entry'] % 4 == 0, 'Invalid retained model entry'
        assert _integer(m['fixed'], 1, 32) and _integer(m['implicit'], 0, 1) and _integer(m['type_parameters'], 1), 'Invalid retained model arity'
        assert m['basis'] == 'compatible_retained_signature' and isinstance(m['name'], str), 'Invalid retained model basis'
        assert len(m['declared_types']) == m['fixed'] and all(isinstance(v, str) for v in m['declared_types']), 'Invalid declared type metadata'
        assert m['entry'] not in models, 'Duplicate retained model'
        models[m['entry']] = m
    prologues = {p['target']: p for p in graph.get('descriptor_prologues', [])}
    assert len(prologues) == len(graph.get('descriptor_prologues', [])), 'Duplicate descriptor prologue'
    edges = {e['site']: e for e in graph['edges']}
    nodes = {n['start']: n for n in graph['nodes']}
    for s in graph['call_input_shapes']:
        assert abi['supported'] and abi['word_bytes'] == 8, 'Shape without verified ABI'
        assert all(_integer(s[k], 0 if k == 'pool_index' else 1) for k in ('site', 'payload', 'target', 'load', 'pool_index', 'count', 'word_bytes')), 'Invalid shape integers'
        assert s['site'] % 4 == s['load'] % 4 == 0 and s['load'] == s['site'] - 4, 'Nonadjacent descriptor load'
        edge = edges[s['site']]; node = nodes[s['payload']]
        assert node['decoded'] and node['start'] <= s['load'] < s['site'] < node['end'], 'Shape outside decoded payload'
        assert edge['kind'] == 'call' and edge['source'] == s['payload'] and edge['target'] == s['target'], 'Shape has wrong original call'
        descriptor = descriptors[s['pool_index']]
        assert s['word_bytes'] == 8 and s['count'] == descriptor['count'], 'Input counts disagree'
        if s['basis'] == 'immediate_descriptor_fixed_stack':
            model = models[s['target']]
            assert descriptor['positional'] == descriptor['count'] and s['count'] == model['fixed'] and descriptor['type_arguments'] in (0, model['type_parameters']), 'Retained model mismatch'
        else:
            assert graph.get('format', 0) >= 35 and s['basis'] == 'callee_descriptor_prologue' and s['target'] in prologues, 'Missing descriptor prologue'
            p = prologues[s['target']]
            if p.get('parameter', False):
                offset = s['count']*8+p['count_bias']*4+p['frame_load_offset']-16
                assert 0 <= offset < s['count']*8 and offset%8 == 0, 'Parameter proof reads outside supplied packet'
        proof = s['proof']
        assert 2 <= len(proof) <= 128 and proof == sorted(set(proof)) and all(_integer(p, node['start'], s['site']) and p % 4 == 0 for p in proof), 'Malformed supplied-input proof'
        assert proof[-2:] == [s['load'], s['site']], 'Missing descriptor load/call proof'
        assert s['site'] not in result, 'Duplicate call-input shape'
        result[s['site']] = s
    assert set(descriptors) == {s['pool_index'] for s in result.values()}, 'Unused or missing descriptor catalogue entries'
    assert set(models) == {s['target'] for s in result.values() if s['basis'] == 'immediate_descriptor_fixed_stack'}, 'Unused or missing signature models'
    rejected = set()
    for row in graph['call_input_rejections']:
        assert row['site'] in edges and edges[row['site']]['kind'] == 'call' and row['site'] not in result and row['site'] not in rejected, 'Invalid rejected input site'
        assert row['reason'] in {'shared_retained_entry', 'native_or_abstract_model', 'unsupported_signature_model',
            'inconsistent_implicit_count', 'unbounded_model_entry', 'unsupported_model_arity',
            'no_immediate_descriptor_pool_load', 'unsupported_descriptor_object', 'unsupported_sdk_abi',
            'unsupported_descriptor_shape', 'incompatible_retained_model', 'nonadjacent_descriptor_load',
            'descriptor_load_bypass', 'not_direct_bl', 'wrong_original_target', 'unsupported_descriptor_load',
            'unproved_descriptor_pool_load', 'no_checked_descriptor_prologue', 'descriptor_parameter_outside_packet'}, 'Unknown input rejection reason'
        rejected.add(row['site'])
    if not abi['supported']:
        assert not descriptors and not models and not result and not rejected, 'Unverified ABI exported supplied-input evidence'
    return result


def input_records(graph, site=None, *, include_unknown=False):
    table = shapes(graph)
    edges = {e['site']: e for e in graph['edges'] if e['site'] in table and (site is None or e['site'] == site)}
    seen = set()

    def add(edge, values, bindings=None, collection=None):
        shape = table[edge['site']]
        ordinary = {(v['sp_offset'], v['kind'], int(v['value'], 16)) for v in edge.get('stack_inputs', [])}
        mapped = {}
        for v in values:
            offset = v['sp_offset']
            if offset < 0 or offset % 8 or offset >= shape['count']*8:
                continue
            assert offset not in mapped, 'Duplicate supplied-input physical slot'
            kind, amount = v['kind'], int(v['value'], 16)
            assert kind in ('word', 'heap_class') and _integer(amount, 1 if kind == 'heap_class' else 0, (1 << 32)-1 if kind == 'heap_class' else (1 << 64)-1), 'Invalid supplied-input value'
            mapped[offset] = (kind, amount)
        for index in range(shape['count']):
            offset = (shape['count'] - 1 - index)*8
            value = mapped.get(offset)
            if value is None:
                if not include_unknown or bindings is not None:
                    continue
                value = ('unknown', None)
            kind, amount = value
            if bindings is not None and (offset, kind, amount) in ordinary:
                continue
            scope = None if bindings is None else tuple(sorted((v['site'], v['callee'], v['class_id']) for v in bindings))
            assert bindings is None or scope, 'Missing supplied-input conditions'
            key = (edge['site'], index, kind, amount, scope)
            if key in seen:
                continue
            seen.add(key)
            yield dict(payload=edge['source'], site=edge['site'], index=index, sp_offset=offset,
                       kind=kind, value=amount, load=shape['load'], bindings=bindings, collection=collection)

    for edge in edges.values():
        yield from add(edge, edge.get('stack_inputs', []))
    for family in FAMILIES:
        for context in graph.get(family, []):
            for observation in context.get('stack_observations', []):
                edge = edges.get(observation['site'])
                if edge is not None:
                    assert context['payload'] == edge['source'], 'Conditional input has wrong payload'
                    yield from add(edge, observation['values'], context['return_bindings'], family)


def check_shapes(graph, audit, read):
    """Cross-check typed SDK data and original call/load words independently.

    The parent annotation checker additionally verifies complete pool provenance
    backwards from original bytes; this check ties that reference to this use.
    """
    table = shapes(graph)
    if graph.get('format', 0) < 34:
        return 0
    abi = graph['call_input_abi']
    if not abi['supported']:
        if audit is not None and 'call_input_abi' in audit:
            assert audit['call_input_abi']['supported'] is False, 'Graph hides an audited input ABI'
        return 0
    assert audit is not None, 'Supplied-input shapes require an independent SDK audit'
    expected_abi = dict(audit['call_input_abi'])
    assert {k: abi[k] for k in expected_abi} == expected_abi and abi['reason'] == 'verified_compiler_policy', 'Input ABI differs from SDK audit'
    audited_descriptors = {v['pool_index']: v for v in audit['call_input_descriptors']}
    assert len(audited_descriptors) == len(audit['call_input_descriptors']), 'Duplicate audited descriptor'
    for d in graph['call_input_descriptors']:
        assert d == audited_descriptors[d['pool_index']], 'Descriptor differs from typed SDK audit'
    if graph.get('format', 0) >= 35:
        from descriptor_prologues import verify
        assert graph['descriptor_prologue_abi'] == audit['descriptor_prologue_abi'], 'Descriptor prologue ABI differs from SDK audit'
        assert {p['target'] for p in graph['descriptor_prologues']} == {v['target'] for v in table.values() if v['basis'] == 'callee_descriptor_prologue'}
        for row in graph['descriptor_prologues']:
            verify(row, graph['descriptor_prologue_abi'], read)
    owners = defaultdict(list)
    for f in audit['function_metadata']:
        owners[f['entry']].append(f)
    models = {m['entry']: m for m in graph['call_input_models']}
    for target, m in models.items():
        group = owners[target]
        assert len(group) == 1, 'Shared retained function entry has no unique metadata model'
        f = group[0]; p = f['call_input_model']
        assert p and f['kind'] == 0 and not p['native'] and not p['abstract'], 'Unsupported retained function kind'
        assert p['optional'] == p['parent_type_arguments'] == 0 and p['type_parameters'] > 0, 'Unsupported retained signature'
        assert p['implicit'] == p['implicit_from_kind'] == (0 if p['static'] else 1), 'Inconsistent implicit model'
        assert (m['fixed'], m['implicit'], m['type_parameters'], m['name']) == (p['fixed'], p['implicit'], p['type_parameters'], f['name']), 'Retained signature differs from SDK audit'
        assert m['declared_types'] == p['declared_types'], 'Declared types differ from SDK audit'
    references = {v['site']: v for v in graph['references'] if v['kind'] == 'pool' and v['access'] == 'load' and v['width'] == 8 and v['pool_index'] is not None}
    entries = {v['address'] for n in graph['nodes'] for v in n.get('names', [])}
    entries.update(e['target'] for e in graph['edges'] if e.get('target') is not None)
    entries.update(graph.get('dispatch_table', {}).get('entries', []))
    # Conditional branches are deliberately absent from the call-edge list.
    # Read every decoded original payload, including cross-payload predecessors.
    for node in graph['nodes']:
        if not node['decoded']:
            continue
        raw = read(node['start'], node['end'] - node['start'])
        assert len(raw) == node['end'] - node['start'] and len(raw) % 4 == 0, 'Truncated payload for input-entry audit'
        for i, (word,) in enumerate(struct.iter_unpack('<I', raw)):
            shift, bits = (0, 26) if word & 0x7c000000 == 0x14000000 else (
                (5, 19) if word & 0xff000010 == 0x54000000 or word & 0x7e000000 == 0x34000000 else
                (5, 14) if word & 0x7e000000 == 0x36000000 else (0, 0))
            if bits:
                delta = (word >> shift) & ((1 << bits)-1)
                if delta & (1 << (bits-1)):
                    delta -= 1 << bits
                entries.add(node['start'] + i*4 + delta*4)

    for s in table.values():
        assert s['site'] not in entries, 'A known entry bypasses the descriptor load'
        word = int.from_bytes(read(s['load'], 4), 'little')
        call = int.from_bytes(read(s['site'], 4), 'little')
        assert len(read(s['load'], 4)) == len(read(s['site'], 4)) == 4, 'Truncated original instruction'
        assert word & 0xffc00000 == 0xf9400000 or word & 0xffe00c00 == 0xf8400000, 'Not a full-width immediate descriptor load'
        assert word & 31 == abi['descriptor_register'] and (word >> 5) & 31 != 31, 'Wrong descriptor register or base'
        assert call & 0xfc000000 == 0x94000000, 'Not an original direct BL'
        delta = call & 0x3ffffff
        if delta & 0x2000000:
            delta -= 0x4000000
        assert s['site'] + delta*4 == s['target'], 'Wrong original call target'
        ref = references[s['load']]
        assert ref['payload'] == s['payload'] and ref['pool_index'] == s['pool_index'], 'Descriptor use differs from pool provenance'
        assert ref['base_register'] == 'x' + str((word >> 5) & 31), 'Descriptor base differs from original instruction'
        assert s['proof'] == sorted(set(ref['proof'] + [s['load'], s['site']])), 'Descriptor use proof differs from checked reference'
        profile = graph['profile']
        assert ref['offset'] == profile['pool_data_offset'] + s['pool_index']*profile['pool_slot_size'], 'Wrong descriptor pool index'
    starts = [n['start'] for n in graph['nodes']]
    expected = set()
    for e in graph['edges']:
        if e['kind'] != 'call' or len(owners[e['target']]) != 1:
            continue
        f = owners[e['target']][0]; p = f.get('call_input_model')
        if not p or f['kind'] != 0 or p['native'] or p['abstract'] or p['optional'] or p['parent_type_arguments'] or not p['type_parameters']:
            continue
        if p['implicit'] != p['implicit_from_kind'] or p['implicit'] != (0 if p['static'] else 1) or not 1 <= p['fixed'] <= 32:
            continue
        pos = bisect.bisect_right(starts, e['target']) - 1
        if pos < 0 or e['target'] >= graph['nodes'][pos]['end'] or e['target'] % 4 or e['site'] in entries:
            continue
        ref = references.get(e['site'] - 4)
        if not ref or ref['payload'] != e['source']:
            continue
        d = audited_descriptors.get(ref['pool_index'])
        if not d or d['count'] != d['size'] or d['count'] != d['positional'] or d['count'] != p['fixed'] or d['type_arguments'] not in (0, p['type_parameters']):
            continue
        word = int.from_bytes(read(ref['site'], 4), 'little')
        if not (word & 0xffc00000 == 0xf9400000 or word & 0xffe00c00 == 0xf8400000) or word & 31 != abi['descriptor_register']:
            continue
        proof = sorted(set(ref['proof'] + [ref['site'], e['site']]))
        if len(proof) > 128 or proof[0] < e['source'] or proof[-2:] != [ref['site'], e['site']]:
            continue
        expected.add(e['site'])
    assert {site for site,s in table.items() if s['basis'] == 'immediate_descriptor_fixed_stack'} == expected, 'Retained-model supplied-input coverage differs from original words and SDK metadata'
    return len(table)
