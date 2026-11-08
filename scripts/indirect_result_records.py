"""Read explicit scoped indirect results; original-byte proof checking is separate."""


def _require(value, message):
    if not value:
        raise ValueError(message)


def _summary_map(rows):
    result = {}
    for entry, cid in rows:
        _require(type(entry) is int and entry > 0 and entry % 4 == 0 and entry not in result,
                 'Invalid indirect-result producer identity')
        _require(type(cid) is int and 0 < cid <= 0xffffffff, 'Invalid indirect-result producer class')
        result[entry] = cid
    return result


def scope_key(registers, stack, bindings):
    """Canonical numeric conditions shared by query and rendering checks."""
    return (tuple(sorted((int(v['register'][1:]), v['class_id']) for v in registers)),
            tuple(sorted((v['sp_offset'], v['kind'], int(v['value'], 16)) for v in stack)),
            tuple(sorted((v['site'], v['callee'], v['class_id']) for v in bindings)))


def indirect_results(graph, site=None):
    collections = ('register_contexts', 'call_result_contexts', 'sdk_stub_producer_contexts',
                   'sdk_stub_caller_contexts')
    present = False
    for stage in collections:
        for context in graph.get(stage, []):
            certificate = context.get('certificate', {})
            _require(isinstance(certificate, dict), 'Malformed indirect-result certificate')
            present |= bool(certificate.get('indirect_returns', []))
    if not present:
        return []
    edges = {e['site']: e for e in graph['edges']}
    nodes = {n['start']: n for n in graph['nodes']}
    machine = _summary_map(graph.get('receiver_metadata', {}).get('machine_return_classes', []))
    sdk = _summary_map(graph.get('sdk_stub_return_summaries', []))
    results = []
    for stage in collections:
        for context in graph.get(stage, []):
            certificate = context.get('certificate', {})
            _require(isinstance(certificate, dict), 'Malformed indirect-result certificate')
            rows = certificate.get('indirect_returns', [])
            if not rows:
                continue
            _require(graph.get('format', 4) >= 28, 'Indirect-result records require graph format 28')
            _require(graph.get('receiver_metadata', {}).get('word_return_register') == 'x0',
                     'Indirect result has no configured X0 ABI')
            payload = context['payload']
            _require(payload in nodes and context['certificate']['payload'] == payload,
                     'Indirect-result context has no matching payload')
            registers = context.get('register_inputs', [])
            stack = context.get('inputs', [])
            bindings = context.get('return_bindings', [])
            callers = context.get('callers', [])
            if stage == 'register_contexts':
                _require(registers and callers and len(set(callers)) == len(callers),
                         'Indirect result has no unique original caller scope')
                _require(all(s in edges and edges[s]['kind'] == 'call' and edges[s].get('target') == payload
                             for s in callers), 'Indirect-result caller target mismatch')
            else:
                _require(bindings, 'Indirect result has no prior-call binding scope')
            seen = set()
            for value in registers:
                name = value['register']
                _require(isinstance(name, str) and name.startswith('x') and name[1:].isdigit() and
                         name == 'x' + str(int(name[1:])) and 0 <= int(name[1:]) < 15 and name not in seen,
                         'Invalid indirect-result register condition')
                _require(type(value['class_id']) is int and 0 < value['class_id'] <= 0xffffffff,
                         'Invalid indirect-result register class')
                seen.add(name)
            seen = set()
            for value in stack:
                offset = value['sp_offset']
                _require(type(offset) is int and 0 <= offset <= 248 and offset % 8 == 0 and offset not in seen,
                         'Invalid indirect-result stack condition')
                _require(value['kind'] in ('word', 'heap_class') and isinstance(value['value'], str),
                         'Invalid indirect-result stack value')
                number = int(value['value'], 16)
                _require(0 <= number <= 0xffffffffffffffff and
                         (value['kind'] != 'heap_class' or 0 < number <= 0xffffffff),
                         'Invalid indirect-result stack class or word')
                seen.add(offset)
            seen = set()
            for value in bindings:
                call = edges.get(value['site'])
                _require(call is not None and call['source'] == payload and call['kind'] == 'call' and
                         call.get('target') == value['callee'] and value['site'] not in seen,
                         'Invalid indirect-result prior-call condition')
                _require(type(value['class_id']) is int and 0 < value['class_id'] <= 0xffffffff,
                         'Invalid indirect-result prior-call class')
                seen.add(value['site'])
            summaries = machine | sdk if stage == 'sdk_stub_caller_contexts' else machine
            resolutions = {v['site']: v for v in context['resolutions']}
            seen = set()
            for row in rows:
                _require(set(row) == {'site', 'callee', 'class_id', 'register', 'basis', 'proof'},
                         'Malformed indirect-result record')
                _require(all(type(row[k]) is int for k in ('site', 'callee', 'class_id')) and row['site'] not in seen,
                         'Invalid or duplicate indirect-result address')
                seen.add(row['site'])
                edge = edges.get(row['site'])
                _require(edge is not None and edge['source'] == payload and edge['kind'] == 'indirect_call',
                         'Indirect result has no matching original indirect call')
                resolution = resolutions.get(row['site']) or edge.get('static_dispatch')
                _require(resolution is not None and resolution['snapshot_target'] == row['callee'],
                         'Indirect result disagrees with its resolved target')
                _require(row['register'] == 'x0' and row['basis'] == 'machine_return_summary' and
                         summaries.get(row['callee']) == row['class_id'], 'Indirect result lacks a matching closed producer')
                proof = row['proof']
                _require(isinstance(proof, list) and 0 < len(proof) <= 128 and
                         all(type(p) is int and nodes[payload]['start'] <= p < nodes[payload]['end'] and p % 4 == 0 for p in proof),
                         'Invalid indirect-result proof range')
                _require(proof == sorted(set(proof)) and row['site'] in proof and resolution['load'] in proof,
                         'Indirect result lacks call/target provenance')
                if site is None or row['site'] == site:
                    results.append(dict(row, payload=payload, stage=stage, entry_register_inputs=registers,
                                        entry_stack_inputs=stack, return_bindings=bindings, callers=callers))
    return results
