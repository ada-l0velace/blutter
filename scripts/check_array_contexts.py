"""Check array context bindings against their separately checked caller claims."""


def check_array_bindings(graph, stacks, arrays, contract, allocations):
    contexts = graph.get('array_contexts', [])
    assert graph.get('format', 4) >= 15 or not contexts
    assert len(contexts) <= 4096
    edges = {e['site']: e for e in graph['edges']}
    nodes = {n['start'] for n in graph['nodes']}
    keys, callers = set(), set()
    for context in contexts:
        assert contract and type(context['payload']) is int and context['payload'] in nodes
        assert context['scope'] == 'entry_block'
        sites = context['callers']
        assert sites and all(type(s) is int for s in sites) and len(set(sites)) == len(sites)
        values = {}
        assert 0 < len(context['inputs']) <= 32
        for item in context['inputs']:
            offset, kind, value = item['sp_offset'], item['kind'], int(item['value'], 16)
            assert type(offset) is int and 0 <= offset <= 248 and offset % 8 == 0 and offset not in values
            assert kind in ('word', 'heap_class') and 0 <= value < 1 << 64
            assert kind != 'heap_class' or value < 1 << graph['receiver_metadata']['class_id_bits']
            values[offset] = kind, value
        binding = context['array_input']
        offset, length, elements = binding['sp_offset'], binding['length'], binding['elements']
        assert type(offset) is int and 0 <= offset <= 248 and offset % 8 == 0
        assert type(length) is int and 1 <= length <= 32 and 0 < len(elements) <= 32
        assert len(dict(elements)) == len(elements)
        for index, cid in elements:
            assert type(index) is type(cid) is int and 0 <= index < length and 0 <= cid < 1 << graph['receiver_metadata']['class_id_bits']
        assert values.get(offset) == ('heap_class', allocations[contract[0]])
        key = context['payload'], tuple(sorted(values.items())), offset, length, tuple(sorted(map(tuple, elements)))
        assert key not in keys, 'Duplicate array context'
        keys.add(key)
        for site in sites:
            edge = edges[site]
            assert edge['kind'] == 'call' and edge['target'] == context['payload'] and site in stacks and site in arrays
            supplied = {v['sp_offset']: (v['kind'], int(v['value'], 16)) for v in stacks[site]}
            assert all(supplied.get(k) == v for k, v in values.items()), 'Array context changes scalar inputs'
            assert any(v['sp_offset'] == offset and v['length'] == length and dict(v['elements']) == dict(elements) for v in arrays[site]), 'Array binding differs from caller contents'
            callers.add(site)
        reads = context['array_reads']
        assert len({v['site'] for v in reads}) == len(reads)
        assert not context.get('forwarded_returns')
        if context['status'] == 'bound_only':
            assert not reads and not context['resolutions'] and context['certificate'] is None
        else:
            assert context['status'] == 'read_proved' and reads and context['certificate'] is not None
            assert context['certificate']['payload'] == context['payload']
            assert len({v['site'] for v in context['resolutions']}) == len(context['resolutions'])
    return callers
