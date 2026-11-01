"""Check exact-site helper result bindings without feeding consumers into proofs."""


def check_result_bindings(graph, machine_returns):
    contexts = graph.get('call_result_contexts', [])
    assert graph.get('format', 4) >= 24 or not contexts
    edges = {e['site']: e for e in graph['edges']}
    nodes = {n['start'] for n in graph['nodes']}
    targeted = graph.get('targeted_call_result_analysis')
    assert len(contexts) <= 4096 + (1 if targeted else 0)
    if targeted is not None:
        assert graph.get('format', 4) >= 25
        assert set(targeted) == {'payload', 'status', 'candidate_payloads', 'attempted_payloads',
                                 'transfer_steps', 'payload_limit', 'step_limit'}
        assert type(targeted['payload']) is int and targeted['payload'] in nodes
        assert targeted['payload'] > 0 and targeted['payload'] % 4 == 0
        for key in ('candidate_payloads', 'attempted_payloads', 'transfer_steps', 'payload_limit', 'step_limit'):
            assert type(targeted[key]) is int
        assert targeted['payload_limit'] == 1 and targeted['step_limit'] == 1000000
        assert 0 <= targeted['attempted_payloads'] <= targeted['candidate_payloads'] <= 1
        assert 0 <= targeted['transfer_steps'] <= targeted['step_limit']
        status = targeted['status']
        assert status in ('added', 'already_recorded', 'no_retained_bytes', 'unsupported_return_abi',
                          'no_return_bindings', 'no_new_facts', 'no_certificate', 'step_limit')
        present = any(c['payload'] == targeted['payload'] for c in contexts)
        assert present == (status in ('added', 'already_recorded'))
        if status in ('added', 'no_new_facts', 'no_certificate', 'step_limit'):
            assert targeted['candidate_payloads'] == targeted['attempted_payloads'] == 1
        else:
            assert targeted['candidate_payloads'] == targeted['attempted_payloads'] == targeted['transfer_steps'] == 0
        if status == 'step_limit':
            assert targeted['transfer_steps'] == targeted['step_limit']
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
