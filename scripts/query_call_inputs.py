#!/usr/bin/env python3
"""Show supplied Dart input order, physical values and separate signature models.

Run the original-byte/VM audit checker before interpreting these exported facts.
"""
import argparse
import json
from pathlib import Path
from graph_io import load_graph
from call_input_shapes import input_records, shapes


def query(graph, site):
    edge = next((e for e in graph['edges'] if e['site'] == site), None)
    completion = next((v['operation'] for v in graph.get('async_boundaries', []) if v['site'] == site and
                       v['operation'] in ('complete_value', 'complete_value_or_future')), None)
    if edge is None or edge['kind'] not in ('call', 'indirect_call') and not (edge['kind'] == 'jump' and completion):
        raise ValueError('site must identify an exported original call or matched async completion')
    table = shapes(graph)
    shape = table.get(site)
    reason = next((r['reason'] for r in graph.get('call_input_rejections', []) if r['site'] == site), None)
    if shape is None and reason is None:
        reason = ('legacy_graph' if graph.get('format', 0) < 34 else
                  graph['call_input_abi']['reason'] if not graph['call_input_abi']['supported'] else
                  'no_supported_retained_model_or_call_form')
    model = next((m for m in graph.get('call_input_models', []) if shape and shape['basis'] == 'immediate_descriptor_fixed_stack' and m['entry'] == shape['target']), None)
    origins = [v for v in graph.get('call_input_origins', []) if v['site'] == site]
    used_pools = {step['pool_index'] for value in origins for step in value['chain'] if step['pool_index'] is not None}
    result = dict(site=site, payload=edge['source'], target=edge.get('target'),
                shape=shape, selection_reason=reason, compatible_signature_model=model,
                inputs=list(input_records(graph, site, include_unknown=True)),
                named_inputs=next((d.get('named', []) for d in graph.get('call_input_descriptors', []) if shape and d['pool_index'] == shape['pool_index']), []),
                physical_stack_inputs=edge.get('stack_inputs', []),
                origins=origins,
                objects=[v for v in graph.get('input_object_catalog', []) if v['pool_index'] in used_pools],
                limits='Supplied order includes implicit inputs and excludes a separate type vector. '
                       'Retained signatures are compatible metadata, not original Function identity. '
                       'Values are partial; conditions are mandatory. Exception and unknown indirect entries are outside this normal-flow proof.')
    if completion and edge['kind'] == 'jump':
        result['async_completion'] = completion
        result['selection_reason'] = 'not_an_ordinary_call_packet'
        result['limits'] = 'Matched SDK completion operand X0. Local provenance is partial and normal-flow qualified; no Future identity or delivered-type claim.'
    return result



def render(result):
    label = "Async completion" if result.get("async_completion") else "Call"
    lines = [f"{label} {result['site']:#x} [payload {result['payload']:#x}]"]
    if not result['shape']:
        lines.append('Supplied input order unavailable: ' + result['selection_reason'])
    else:
        s = result['shape']
        lines.append(f"Checked supplied stack inputs: {s['count']}; descriptor load {s['load']:#x}; pool slot {s['pool_index']}")
        for v in result['inputs']:
            text = ('class ' + hex(v['value']) if v['kind'] == 'heap_class' else
                    'raw word ' + hex(v['value']) if v['kind'] == 'word' else 'value unknown')
            scope = ('normal flow' if v['bindings'] is None else 'under result bindings ' +
                     ','.join(f"{b['site']:#x}@{b['callee']:#x}={b['class_id']:#x}" for b in sorted(v['bindings'], key=lambda b: b['site'])))
            name = next((n['name'] for n in result['named_inputs'] if n['index'] == v['index']), None)
            label = '' if name is None else ', named ' + json.dumps(name, ensure_ascii=True)
            lines.append(f"  supplied input[{v['index']}]{label} (Dart SP+{v['sp_offset']}) -> {text} [{scope}]")
        m = result['compatible_signature_model']
        if m is None:
            lines.append('Compatible signature model: unavailable; order proved from callee descriptor use')
            from input_origins import render_origins
            lines.extend(render_origins(result.get('origins', []), result.get('objects', [])))
            lines.append(result['limits'])
            return '\n'.join(lines)
        lines.append('Compatible retained signature model: ' + json.dumps(m['name'], ensure_ascii=True))
        lines.append(f"  {m['fixed']} fixed inputs, {m['implicit']} implicit, {m['type_parameters']} type parameters")
        for i, name in enumerate(m['declared_types']):
            lines.append(f"  model input[{i}] declared type: {json.dumps(name, ensure_ascii=True)}")
    from input_origins import render_origins
    lines.extend(render_origins(result.get('origins', []), result.get('objects', [])))
    lines.append(result['limits'])
    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('graph', type=Path)
    parser.add_argument('--site', required=True, type=lambda text: int(text, 0))
    parser.add_argument('--json', action='store_true')
    args = parser.parse_args()
    try:
        result = query(load_graph(args.graph), args.site)
    except (OSError, EOFError, ValueError, KeyError, TypeError, AssertionError) as error:
        parser.error(str(error))
    print(json.dumps(result, indent=2) if args.json else render(result))


if __name__ == '__main__':
    main()
