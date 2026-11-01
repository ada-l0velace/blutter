"""Validate physical register bindings and closed-body return claim schemas."""
from check_snapshot_annotations import branch

REGISTERS = {f'x{n}': n for n in range(15)}


def register_claims(graph):
    claims = {}
    bits = graph.get('receiver_metadata', {}).get('class_id_bits', 0)
    for edge in graph['edges']:
        values = edge.get('register_inputs', [])
        if not values:
            continue
        assert graph.get('format', 4) >= 24 and 0 < len(values) <= 15
        assert graph['receiver_metadata']['word_return_register'] == 'x0'
        assert edge['site'] not in claims
        seen = set()
        for value in values:
            assert set(value) == {'register', 'class_id', 'proof'}
            name, cid = value['register'], value['class_id']
            assert name in REGISTERS and name not in seen
            assert name not in {graph['profile'].get(k) for k in ('pool_register', 'thread_register', 'dispatch_register')} | {graph['receiver_metadata'].get('null_register')}
            assert type(cid) is int and 0 < cid < 1 << bits
            assert 0 < len(value['proof']) <= 128
            seen.add(name)
        claims[edge['site']] = values
    return claims


def check_register_bindings(graph, stacks, registers):
    contexts = graph.get('register_contexts', [])
    assert graph.get('format', 4) >= 24 or not contexts
    assert len(contexts) <= 4096
    edges = {e['site']: e for e in graph['edges']}
    nodes = {n['start'] for n in graph['nodes']}
    keys, callers = set(), set()
    for context in contexts:
        assert not {'array_input', 'path_condition', 'trace', 'return_bindings'}.intersection(context)
        assert context['payload'] in nodes and context['certificate']['payload'] == context['payload']
        assert 0 < len(context['register_inputs']) <= 15 and len(context['inputs']) <= 32
        assert context['callers'] and len(set(context['callers'])) == len(context['callers'])
        assert not callers.intersection(context['callers'])
        callers.update(context['callers'])
        supplied = {}
        for item in context['register_inputs']:
            assert set(item) == {'register', 'class_id'}
            name, cid = item['register'], item['class_id']
            assert name in REGISTERS and name not in supplied
            assert name not in {graph['profile'].get(k) for k in ('pool_register', 'thread_register', 'dispatch_register')} | {graph['receiver_metadata'].get('null_register')}
            assert type(cid) is int and 0 < cid < 1 << graph['receiver_metadata']['class_id_bits']
            supplied[name] = cid
        stack = {}
        for item in context['inputs']:
            assert set(item) == {'sp_offset', 'kind', 'value'}
            offset, kind, value = item['sp_offset'], item['kind'], int(item['value'], 16)
            assert type(offset) is int and 0 <= offset < 256 and offset % 8 == 0 and offset not in stack
            assert kind in ('word', 'heap_class') and 0 <= value < 1 << 64
            assert kind != 'heap_class' or value < 1 << graph['receiver_metadata']['class_id_bits']
            stack[offset] = kind, value
        key = context['payload'], tuple(sorted(supplied.items())), tuple(sorted(stack.items()))
        assert key not in keys
        keys.add(key)
        for site in context['callers']:
            edge = edges[site]
            assert edge['kind'] == 'call' and edge['target'] == context['payload'] and site in registers
            actual = {v['register']: v['class_id'] for v in registers[site]}
            assert all(actual.get(k) == v for k, v in supplied.items())
            actual_stack = {v['sp_offset']: (v['kind'], int(v['value'], 16)) for v in stacks.get(site, [])}
            assert all(actual_stack.get(k) == v for k, v in stack.items())
        assert context['normal_return_class'] == context['certificate'].get('normal_return_class')
        for key in ('resolutions', 'forwarded_returns', 'array_length_returns'):
            assert len({v['site'] for v in context.get(key, [])}) == len(context.get(key, []))
        observations = context['stack_observations']
        assert len({v['site'] for v in observations}) == len(observations)
        assert all(set(v) == {'site', 'values'} and v['values'] for v in observations)
    return callers


def machine_returns(graph):
    rows = graph.get('receiver_metadata', {}).get('machine_return_classes', [])
    assert graph.get('format', 4) >= 24 or not rows
    certificates = {c['payload']: c for c in graph.get('receiver_certificates', [])}
    metadata = graph.get('receiver_metadata', {})
    forbidden = set(dict(metadata.get('allocation_returns', []))) | set(dict(metadata.get('nonreturning_calls', [])))
    forbidden.update(row[0] for row in metadata.get('native_return_classes', []))
    forbidden.update(row[0] for row in metadata.get('sdk_stub_return_classes', []))
    values = {}
    for entry, cid in rows:
        assert type(entry) is int and entry > 0 and entry % 4 == 0 and entry not in values and entry not in forbidden
        assert type(cid) is int and 0 < cid < 1 << metadata['class_id_bits']
        assert entry in certificates and certificates[entry].get('normal_return_class') == cid
        values[entry] = cid
    return values


def check_return_summary(certificate, instructions, reached, verified, nonreturning, *, scoped=False):
    """Check exit coverage from original words, independently of CFG lowering."""
    claims = certificate.get('return_classes', [])
    assert len({c['site'] for c in claims}) == len(claims)
    assert verified == {c['site'] for c in claims}, 'Unchecked physical return claim'
    summary = certificate.get('normal_return_class')
    if summary is None:
        return
    assert not scoped and type(summary) is int and reached and reached == verified
    assert all(c['class_id'] == summary for c in claims)
    start, end = instructions[0].address, instructions[-1].address + 4
    for ins in instructions:
        word = int.from_bytes(ins.bytes, 'little')
        transfer = branch(word, ins.address)
        if word & 0xfffffc1f == 0xd65f0000:
            assert word == 0xd65f03c0, 'Alternate return register is not a normal-return proof'
        if transfer and transfer[0] not in ('call', 'indirect_call'):
            assert transfer[0] != 'indirect_jump'
            assert start <= transfer[1] < end and (transfer[1]-start) % 4 == 0, 'Unproved escaping return path'
    last = instructions[-1]
    word = int.from_bytes(last.bytes, 'little')
    transfer = branch(word, last.address)
    trap = word & 0xffe0001f in (0xd4200000, 0xd4400000)
    assert word == 0xd65f03c0 or trap or transfer and (
        transfer[0] == 'jump' or transfer[0] == 'call' and transfer[1] in nonreturning), 'Unproved fallthrough exit'
