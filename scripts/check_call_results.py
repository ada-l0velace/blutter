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
    return contexts + check_sdk_result_bindings(graph, machine_returns, conditional, edges, nodes)


def check_sdk_result_bindings(graph, machine_returns, conditional, edges, nodes):
    producers = graph.get('sdk_stub_producer_contexts', [])
    callers = graph.get('sdk_stub_caller_contexts', [])
    rows = graph.get('sdk_stub_return_summaries', [])
    failures = graph.get('sdk_stub_decode_failures', [])
    if graph.get('format', 4) < 26:
        assert not producers and not callers and not rows and not failures
        return []
    sdk = {entry: cid for entry, cid, _ in graph['receiver_metadata'].get('sdk_stub_return_classes', [])}
    assert len(set(failures)) == len(failures)
    assert all(type(v) is int and v in nodes for v in failures)
    assert not set(failures).intersection(c['payload'] for c in producers)
    summaries = {}
    for entry, cid in rows:
        assert type(entry) is int and type(cid) is int and entry not in summaries and entry not in machine_returns and entry not in sdk
        assert entry in nodes and 0 < cid < 1 << graph['receiver_metadata']['class_id_bits']
        summaries[entry] = cid
    expected = {c['payload']: c['normal_return_class'] for c in producers
                if c['normal_return_class'] is not None and c['payload'] not in machine_returns}
    assert summaries == expected
    work = graph.get('sdk_stub_result_analysis', {})
    for kind, contexts in [('producers', producers), ('callers', callers)]:
        assert len(contexts) <= 4096
        if work:
            counters = work[kind]
            assert set(counters) == {'candidate_payloads', 'attempted_payloads', 'transfer_steps', 'dropped_callers', 'payload_limit', 'step_limit'}
            assert all(type(v) is int for v in counters.values())
            assert counters['payload_limit'] == 4096 and counters['step_limit'] == 20000000
            assert len(contexts) <= counters['attempted_payloads'] <= counters['candidate_payloads'] <= 4096
            assert 0 <= counters['transfer_steps'] <= 20000000 and counters['dropped_callers'] >= 0
        seen = set()
        for context in contexts:
            payload = context['payload']
            assert type(payload) is int and payload in nodes and payload not in seen
            seen.add(payload)
            assert context['inputs'] == [] and context['certificate']['payload'] == payload
            assert not {'register_inputs', 'array_input', 'path_condition', 'trace', 'callers'}.intersection(context)
            assert context['normal_return_class'] == context['certificate']['normal_return_class']
            assert context['return_bindings']
            sites = set()
            has_sdk_summary = False
            for binding in context['return_bindings']:
                assert set(binding) == {'site', 'callee', 'class_id', 'basis'}
                site, callee, cid = (binding[k] for k in ('site', 'callee', 'class_id'))
                assert all(type(v) is int for v in (site, callee, cid)) and site not in sites
                sites.add(site)
                assert 0 < cid < 1 << graph['receiver_metadata']['class_id_bits']
                edge = edges[site]
                assert edge['source'] == payload and edge['kind'] == 'call' and edge['target'] == callee
                basis = binding['basis']
                if kind == 'producers':
                    assert basis == 'sdk_stub_identity' and sdk.get(callee) == cid
                elif basis == 'sdk_stub_summary':
                    assert summaries.get(callee) == cid
                    has_sdk_summary = True
                elif basis == 'machine_return_summary':
                    assert machine_returns.get(callee) == cid
                else:
                    assert basis == 'register_context' and conditional.get(site) == (callee, cid)
            assert kind == 'producers' or has_sdk_summary
            for key in ('resolutions', 'stack_observations', 'array_observations'):
                assert len({v['site'] for v in context[key]}) == len(context[key])
    return producers + callers
