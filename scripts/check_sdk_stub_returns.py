"""Check return-only SDK-stub identities against a separate numerical VM audit."""
from collections import defaultdict

from check_snapshot_annotations import branch


def check_sdk_stub_returns(graph, read, audit):
    metadata = graph.get('receiver_metadata', {})
    rows = metadata.get('sdk_stub_return_classes', [])
    claims = [e for e in graph['edges'] if e.get('sdk_stub_return') is not None]
    if graph.get('format', 4) < 26:
        assert not rows and not claims
        return {}, 0
    if not rows and not claims and not audit.get('sdk_stub_return_sdk'):
        return {}, 0
    sdk = audit['sdk_stub_return_sdk']
    assert len(sdk) == 1
    kind, cid = sdk[0]
    assert kind == 'allocate_growable_array'
    assert type(cid) is int and 0 < cid < 1 << metadata['class_id_bits']
    assert metadata['word_return_register'] == audit.get('word_return_register')
    nodes = {n['start']: n for n in graph['nodes']}
    stubs = {s['entry']: s['size'] for s in audit['known_stubs']}
    reference = audit.get('sdk_stub_return_reference')
    reference_bytes = None
    if reference is not None:
        assert set(reference) == {'entry', 'end', 'kind'} and reference['kind'] == kind
        assert all(type(reference[k]) is int for k in ('entry', 'end'))
        entry, end = reference['entry'], reference['end']
        assert 0 < entry < end < 1 << 64 and entry % 4 == end % 4 == 0
        assert end-entry <= 1 << 20 and stubs.get(entry) == end-entry
        reference_bytes = read(entry, end-entry)
        assert len(reference_bytes) == end-entry
    aliases = defaultdict(list)
    for identity in audit['sdk_stub_return_identities']:
        assert set(identity) == {'entry', 'payload', 'end', 'kind'}
        assert all(type(identity[k]) is int and 0 <= identity[k] < 1 << 64
                   for k in ('entry', 'payload', 'end'))
        assert type(identity['kind']) is str
        entry, payload, end = (identity[k] for k in ('entry', 'payload', 'end'))
        match = None
        if (metadata['word_return_register'] == 'x0' and identity['kind'] == kind and
                entry > 0 and entry % 4 == 0 and entry == payload and end > entry and end % 4 == 0 and
                payload in nodes and nodes[payload]['end'] == end and stubs.get(entry) == end-entry and
                reference_bytes is not None and len(reference_bytes) == end-entry and read(entry, end-entry) == reference_bytes):
            match = cid, kind
        aliases[entry].append(match)
    accepted = {entry: values[0] for entry, values in aliases.items()
                if values[0] is not None and all(v == values[0] for v in values)}
    selected = {}
    for entry, value, contract in rows:
        assert type(entry) is int and type(value) is int and entry not in selected
        assert accepted.get(entry) == (value, contract)
        selected[entry] = value, contract
    assert selected == accepted, 'Missing or conflicting SDK-stub return contract'
    for field in ('allocation_returns', 'native_return_classes', 'machine_return_classes', 'nonreturning_calls'):
        assert not set(selected).intersection(v[0] for v in metadata.get(field, []))
    count = 0
    for edge in graph['edges']:
        claim = edge.get('sdk_stub_return')
        expected = selected.get(edge.get('target')) if edge['kind'] == 'call' else None
        if expected is None:
            assert claim is None
            continue
        assert claim and set(claim) == {'callee', 'class_id', 'register', 'contract', 'condition', 'basis'}
        assert type(claim['callee']) is int and type(claim['class_id']) is int
        assert claim == {'callee': edge['target'], 'class_id': expected[0], 'register': 'x0',
                         'contract': expected[1], 'condition': 'normal_return', 'basis': 'matched_sdk_stub_identity'}
        assert branch(int.from_bytes(read(edge['site'], 4), 'little'), edge['site']) == ('call', edge['target'])
        count += 1
    return {entry: value[0] for entry, value in selected.items()}, count
