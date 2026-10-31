"""Check array context bindings against their separately checked caller claims."""


def check_array_bindings(graph, stacks, arrays, contract, allocations):
    normal = graph.get('array_contexts', [])
    paths = graph.get('array_path_contexts', [])
    assert graph.get('format', 4) >= 18 or not paths
    assert len(paths) <= 4096
    traces = graph.get('array_entry_traces', [])
    assert graph.get('format', 4) >= 19 or not traces
    assert len(traces) <= 4096
    results = graph.get('array_result_traces', [])
    assert graph.get('format', 4) >= 20 or not results
    assert len(results) <= 4096
    contexts = normal + paths + traces + results
    assert graph.get('format', 4) >= 15 or not contexts
    assert len(normal) <= 4096
    edges = {e['site']: e for e in graph['edges']}
    nodes = {n['start'] for n in graph['nodes']}
    keys, callers = set(), set()
    for number, context in enumerate(contexts):
        path_mode = number >= len(normal)
        trace_mode = number >= len(normal)+len(paths)
        use_mode = number >= len(normal)+len(paths)+len(traces)
        assert ('trace' in context) == trace_mode
        assert ('path_condition' in context) == path_mode
        assert contract and type(context['payload']) is int and context['payload'] in nodes
        if path_mode:
            assert context['scope'] == ('entry_result_use' if use_mode else 'entry_prefix' if trace_mode else 'initial_stack_check_fast_path') and context['status'] != 'bound_only'
        else:
            assert context['scope'] == 'entry_block' or graph.get('format', 4) >= 17 and context['scope'] == 'entry_chain'
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
        key = path_mode, trace_mode, use_mode, context['payload'], tuple(sorted(values.items())), offset, length, tuple(sorted(map(tuple, elements)))
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
        lengths = context.get('array_length_returns', [])
        assert graph.get('format', 4) >= 17 or not lengths
        assert len({v['site'] for v in lengths}) == len(lengths)
        assert len({v['site'] for v in context['resolutions']}) == len(context['resolutions'])
        assert len({v['site'] for v in reads}) == len(reads)
        assert not context.get('forwarded_returns')
        if trace_mode:
            indexed = context['indexed_returns']
            assert context['certificate']['payload'] == context['payload']
            assert indexed and context['status'] == ('result_dispatch_proved' if use_mode else 'indexed_result_proved') and context['certificate'] is not None
            assert len(indexed) == 1 and indexed[0]['site'] == context['trace']['getter' if use_mode else 'stop']
            if use_mode:
                assert len(context['resolutions']) == 1 and context['resolutions'][0]['site'] == context['trace']['stop']
        elif context['status'] == 'bound_only':
            assert not reads and not lengths and not context['resolutions'] and context['certificate'] is None
        elif context['status'] == 'length_proved':
            assert graph.get('format', 4) >= 17 and not reads and lengths and context['certificate'] is not None
            assert context['certificate']['payload'] == context['payload']
        else:
            assert context['status'] == 'read_proved' and reads and context['certificate'] is not None
            assert context['certificate']['payload'] == context['payload']
    return callers
