"""Validate return-only SDK contracts from raw retained-Function audit records."""
from collections import defaultdict

from check_snapshot_annotations import branch


def check_native_returns(graph, read, audit):
    rows = graph.get('receiver_metadata', {}).get('native_return_classes', [])
    claims = [e for e in graph['edges'] if e.get('native_return') is not None]
    if graph.get('format', 4) < 23:
        assert not rows and not claims
        return {}, 0
    if not rows and not claims and not audit.get('native_return_sdk'):
        return {}, 0
    assert audit and graph['receiver_metadata']['word_return_register'] == audit.get('word_return_register') == 'x0'
    sdk = audit['native_return_sdk']
    assert len(sdk) == 2
    expected = {'allocate_one_byte_string': 'Internal_allocateOneByteString',
                'allocate_two_byte_string': 'Internal_allocateTwoByteString'}
    kinds, classes, contracts = {}, set(), set()
    for kind, cid, native_name, contract in sdk:
        assert type(kind) is int and 0 < kind < 1 << 32 and kind not in kinds
        assert type(cid) is int and 0 < cid < 1 << graph['receiver_metadata']['class_id_bits'] and cid not in classes
        assert contract in expected and native_name == expected[contract] and contract not in contracts
        kinds[kind] = cid, native_name, contract
        classes.add(cid); contracts.add(contract)
    nodes = {n['start']: n for n in graph['nodes']}
    aliases = defaultdict(list)
    fields = {'entry', 'code_entry', 'payload', 'end', 'is_native', 'owns_code',
              'recognized_kind', 'native_name', 'library_uri'}
    for identity in audit['native_return_identities']:
        assert set(identity) == fields
        assert all(type(identity[k]) is int and 0 <= identity[k] < 1 << 64
                   for k in ('entry', 'code_entry', 'payload', 'end', 'recognized_kind'))
        assert type(identity['is_native']) is bool and type(identity['owns_code']) is bool
        assert type(identity['native_name']) is str and type(identity['library_uri']) is str
        entry, payload, end = identity['entry'], identity['payload'], identity['end']
        match = None
        if (identity['is_native'] and identity['owns_code'] and entry > 0 and entry % 4 == 0 and end % 4 == 0 and
                entry == identity['code_entry'] == payload and end > entry and
                payload in nodes and nodes[payload]['end'] == end and identity['library_uri'] == 'dart:_internal'):
            sdk_kind = kinds.get(identity['recognized_kind'])
            if sdk_kind and identity['native_name'] == sdk_kind[1]:
                match = sdk_kind[0], sdk_kind[2]
        aliases[entry].append(match)
    accepted = {entry: values[0] for entry, values in aliases.items()
                if values[0] is not None and all(v == values[0] for v in values)}
    selected = {}
    for entry, cid, contract in rows:
        assert type(entry) is int and type(cid) is int and entry not in selected
        assert accepted.get(entry) == (cid, contract)
        selected[entry] = cid, contract
    assert not set(selected).intersection(dict(graph['receiver_metadata']['allocation_returns']))
    assert not set(selected).intersection(dict(graph['receiver_metadata'].get('nonreturning_calls', [])))
    count = 0
    for edge in graph['edges']:
        claim = edge.get('native_return')
        expected_contract = selected.get(edge.get('target')) if edge['kind'] == 'call' else None
        if expected_contract is None:
            assert claim is None
            continue
        assert claim and set(claim) == {'callee', 'class_id', 'register', 'contract', 'condition', 'basis'}
        assert type(claim['callee']) is int and type(claim['class_id']) is int
        assert claim == {'callee': edge['target'], 'class_id': expected_contract[0], 'register': 'x0',
                         'contract': expected_contract[1], 'condition': 'normal_return', 'basis': 'matched_sdk_native_identity'}
        assert branch(int.from_bytes(read(edge['site'], 4), 'little'), edge['site']) == ('call', edge['target'])
        count += 1
    return {entry: value[0] for entry, value in selected.items()}, count
