"""Check exact-site helper result bindings without feeding consumers into proofs."""


def check_result_bindings(graph, machine_returns):
    contexts = graph.get('call_result_contexts', [])
    assert graph.get('format', 4) >= 24 or not contexts
    assert len(contexts) <= 4096
    edges = {e['site']: e for e in graph['edges']}
    nodes = {n['start'] for n in graph['nodes']}
    conditional = {}
    for context in graph.get('register_contexts', []):
        cid = context['normal_return_class']
        if cid is None:
            continue
        for site in context['callers']:
            assert site not in conditional
            conditional[site] = context['payload'], cid
    seen = set()
    for context in contexts:
        payload = context['payload']
        assert payload in nodes and payload not in seen
        seen.add(payload)
        assert context['inputs'] == [] and context['certificate']['payload'] == payload
        assert not {'register_inputs', 'array_input', 'path_condition', 'trace', 'callers'}.intersection(context)
        assert context['normal_return_class'] == context['certificate'].get('normal_return_class')
        for key in ('resolutions', 'forwarded_returns', 'array_length_returns'):
            assert len({v['site'] for v in context.get(key, [])}) == len(context.get(key, []))
        assert context['return_bindings']
        sites = set()
        for value in context['return_bindings']:
            assert set(value) == {'site', 'callee', 'class_id', 'basis'}
            site, callee, cid = value['site'], value['callee'], value['class_id']
            assert all(type(x) is int for x in (site, callee, cid)) and site not in sites
            assert 0 < cid < 1 << graph['receiver_metadata']['class_id_bits']
            sites.add(site)
            edge = edges[site]
            assert edge['source'] == payload and edge['kind'] == 'call' and edge['target'] == callee
            if value['basis'] == 'machine_return_summary':
                assert machine_returns.get(callee) == cid
            else:
                assert value['basis'] == 'register_context' and conditional.get(site) == (callee, cid)
        for key in ('stack_observations', 'array_observations'):
            observations = context[key]
            assert len({v['site'] for v in observations}) == len(observations)
            assert all(set(v) == {'site', 'values'} and v['values'] for v in observations)
    return contexts
