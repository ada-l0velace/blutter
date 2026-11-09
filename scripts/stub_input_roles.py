"""Read-only joins of proved call targets, SDK stub roles and physical values."""
import re

ROLE_TEXT = {'array_length': 'array length', 'array_type_arguments': 'array type arguments',
             'closure_function': 'closure function', 'closure_context': 'closure context',
             'closure_length_flags': 'closure length/flags'}


def valid_inputs(kind, inputs):
    expected = ({'array_length', 'array_type_arguments'} if kind == 'allocate_array' else
                {'closure_function', 'closure_context'} if kind == 'allocate_closure' else
                {'closure_function', 'closure_context', 'closure_length_flags'}
                if kind in {f'allocate_closure_{n}' for n in range(1, 5)} else set())
    assert expected and len(inputs) == len(expected), 'Unsupported or incomplete stub input ABI'
    assert {v['role'] for v in inputs} == expected, 'Stub input roles disagree with the family'
    registers = [v['register'] for v in inputs]
    assert len(set(registers)) == len(registers) and all(re.fullmatch(r'x(?:[0-9]|1[0-4])', r) for r in registers), 'Invalid stub input registers'


def contracts(graph):
    rows = graph['stub_input_contracts'] if graph.get('format', 0) >= 33 else graph.get('stub_input_contracts', [])
    result = {}
    for row in rows:
        entry, end = row['entry'], row['end']
        assert entry > 0 and entry % 4 == end % 4 == 0 and 0 < end - entry <= 1 << 20, 'Invalid stub input bounds'
        assert row['basis'] == 'matched_sdk_stub_identity', 'Unsupported stub input basis'
        valid_inputs(row['kind'], row['inputs'])
        assert entry not in result, 'Duplicate stub input contract'
        result[entry] = row
    return result


def call_target(edge, resolution=None):
    if edge['kind'] == 'call':
        return edge.get('target')
    if edge['kind'] != 'indirect_call':
        return None
    resolution = resolution if resolution is not None else edge.get('static_dispatch')
    if not resolution:
        return None
    proof = resolution.get('proof', [])
    if not proof:
        return None
    assert len(proof) <= 128 and proof == sorted(set(proof)) and all(p % 4 == 0 for p in proof) and resolution.get('load') in proof, 'Missing or invalid indirect target proof'
    return resolution['snapshot_target']


def input_records(graph, site=None):
    """Class facts retain their scope; words/unknowns are ordinary ABI inputs only."""
    table = contracts(graph)
    edges = {e['site']: e for e in graph['edges'] if site is None or e['site'] == site}

    def add(edge, values, bindings=None, resolution=None):
        target = call_target(edge, resolution) if table else None
        contract = table.get(target)
        roles = {v['register']: v['role'] for v in contract['inputs']} if contract else {}
        ordinary = {(v['register'], v['class_id']) for v in edge.get('register_inputs', [])}
        original_target = call_target(edge) if table else None
        seen = set()
        for value in values:
            reg = value['register']; seen.add(reg)
            role = roles.get(reg)
            if bindings is not None and (reg, value['class_id']) in ordinary and (not role or target == original_target):
                continue
            yield dict(payload=edge['source'], site=edge['site'], register=reg,
                       role=role, callee=target if role else None, kind='class', value=value['class_id'], bindings=bindings)
        if bindings is None and contract:
            constants = {v['register']: int(v['bits'], 16) for v in edge.get('register_constants', [])}
            for reg, role in roles.items():
                if reg not in seen:
                    yield dict(payload=edge['source'], site=edge['site'], register=reg, role=role,
                               callee=target, kind='word' if reg in constants else 'unknown',
                               value=constants.get(reg), bindings=None)

    if graph.get('format', 0) >= 32:
        for edge in edges.values():
            if edge.get('kind') in ('call', 'indirect_call') or graph.get('format', 0) < 33:
                yield from add(edge, edge.get('register_inputs', []))
    for family in ('call_result_contexts', 'sdk_stub_producer_contexts', 'sdk_stub_caller_contexts'):
        for context in graph.get(family, []):
            resolutions = {v['site']: v for v in context['resolutions']}
            for observation in context.get('register_observations', []):
                if observation['site'] in edges:
                    edge = edges[observation['site']]
                    assert edge['source'] == context['payload'] and context['return_bindings'], 'Unscoped stub input observation'
                    yield from add(edge, observation['values'], context['return_bindings'], resolutions.get(edge['site']))


def check_contracts(graph, audit, read):
    table = contracts(graph)
    if graph.get('format', 0) < 33:
        return 0
    assert audit is not None, 'Stub input validation requires the separate VM audit'
    abis = {v['kind']: v['inputs'] for v in audit['stub_input_abis']}
    assert len(abis) == len(audit['stub_input_abis']), 'Duplicate audited stub input ABI'
    for kind, inputs in abis.items():
        valid_inputs(kind, inputs)
    references = {v['kind']: bytes.fromhex(v['bytes']) for v in audit['stub_input_references']}
    assert len(references) == len(audit['stub_input_references']), 'Duplicate audited stub input reference'
    bounds = {n['start']: n['end'] for n in graph['nodes']}
    groups = {}
    for identity in audit['stub_input_identities']:
        entry, end, kind = identity['entry'], identity['end'], identity['kind']
        admitted = None
        if (entry > 0 and entry % 4 == end % 4 == 0 and entry == identity['payload'] and
                0 < end - entry <= 1 << 20 and bounds.get(entry) == end and kind in abis):
            reference = references[kind]
            assert len(reference) == end - entry and read(entry, len(reference)) == reference, 'Stub identity differs from complete SDK bytes'
            admitted = dict(entry=entry, end=end, kind=kind, basis='matched_sdk_stub_identity', inputs=abis[kind])
        if entry in groups and groups[entry] != admitted:
            groups[entry] = None
        else:
            groups.setdefault(entry, admitted)
    expected = {entry: row for entry, row in groups.items() if row is not None}
    assert table == expected, 'Stub input contracts disagree with independently bounded SDK identities'
    return len(table)
