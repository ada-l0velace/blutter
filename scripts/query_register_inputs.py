#!/usr/bin/env python3
"""Inspect partial physical register classes and caller-qualified helper results."""
import argparse
import json
from pathlib import Path


def query(graph, site):
    if graph.get('format', 4) < 24:
        raise ValueError('Register observations require graph format 24 or newer')
    edges = [e for e in graph['edges'] if e['site'] == site]
    if len(edges) != 1:
        raise ValueError('Site must identify exactly one retained call edge')
    edge = edges[0]
    if edge['kind'] not in ('call', 'indirect_call'):
        raise ValueError('Site is not a call')
    labels = {n['start']: n.get('label', '') for n in graph['nodes']}
    contexts = []
    for context in graph.get('register_contexts', []):
        if site not in context['callers']:
            continue
        contexts.append({k: context[k] for k in ('payload', 'inputs', 'register_inputs', 'normal_return_class',
                                                 'resolutions', 'stack_observations')})
    result_contexts = []
    for context in (graph.get('call_result_contexts', []) + graph.get('sdk_stub_producer_contexts', []) +
                    graph.get('sdk_stub_caller_contexts', [])):
        if context['payload'] != edge['source']:
            continue
        bound = any(v['site'] == site for v in context['return_bindings'])
        selected = {key: [v for v in context[key] if bound or v['site'] == site]
                    for key in ('resolutions', 'stack_observations', 'array_observations')}
        if bound or any(selected.values()):
            result_contexts.append(dict(payload=context['payload'], return_bindings=context['return_bindings'], **selected))
    result = {'site': site, 'target': edge.get('target'), 'target_label': labels.get(edge.get('target'), ''),
            'register_inputs': edge.get('register_inputs', []), 'native_return': edge.get('native_return'),
            'sdk_stub_return': edge.get('sdk_stub_return'),
            'callee_normal_return_class': dict(graph['receiver_metadata'].get('machine_return_classes', [])).get(edge.get('target')),
            'contexts': contexts, 'call_result_contexts': result_contexts,
            'limits': 'Partial full-width physical register observations, not complete source arguments. Context results require their explicit caller bindings. Result classes grant no memory or register preservation; unknown remains unknown.'}
    targeted = graph.get('targeted_call_result_analysis')
    if targeted is not None and targeted['payload'] == edge['source']:
        result['targeted_analysis'] = targeted
    return result


def render(result):
    target = 'unresolved' if result['target'] is None else hex(result['target'])
    lines = [f"Call {result['site']:#x} -> {target} {result['target_label']}".rstrip(),
             'Physical heap-class observations (partial):']
    lines.extend(f"  {v['register']}: class {v['class_id']:#x}" for v in result['register_inputs'])
    if not result['register_inputs']:
        lines.append('  none recorded')
    if result['native_return']:
        lines.append(f"Matched SDK normal-return X0: class {result['native_return']['class_id']:#x}")
    if result.get('sdk_stub_return'):
        lines.append(f"Matched SDK stub normal-return X0: class {result['sdk_stub_return']['class_id']:#x} [return only]")
    if result['callee_normal_return_class'] is not None:
        lines.append(f"Callee all-normal-return X0 summary: class {result['callee_normal_return_class']:#x}")
    for context in result['contexts']:
        bindings = ', '.join(f"{v['register']}=class {v['class_id']:#x}" for v in context['register_inputs'])
        lines.append(f'Caller-qualified helper context: {bindings}')
        if context['normal_return_class'] is not None:
            lines.append(f"  All-normal-return X0: class {context['normal_return_class']:#x}")
        for resolution in context['resolutions']:
            lines.append(f"  Dispatch {resolution['site']:#x} -> snapshot {resolution['snapshot_target']:#x}")
        for observation in context['stack_observations']:
            values = ', '.join(f"SP+{v['sp_offset']:#x} {v['kind']} {int(v['value'], 16):#x}" for v in observation['values'])
            lines.append(f"  Call {observation['site']:#x}: {values}")
    if not result['contexts']:
        lines.append('Caller-qualified helper context: none recorded')
    if result.get('targeted_analysis') is not None:
        target = result['targeted_analysis']
        lines.append(f"Selected caller {target['payload']:#x}: {target['status']}; transfer steps {target['transfer_steps']}/{target['step_limit']}")
    for context in result['call_result_contexts']:
        lines.append('Separate caller result propagation:')
        for binding in context['return_bindings']:
            lines.append(f"  Call {binding['site']:#x} normal-return X0: class {binding['class_id']:#x} [{binding['basis']}]")
        for observation in context['array_observations']:
            for value in observation['values']:
                elements = ', '.join(f'[{index}]=class {cid:#x}' for index, cid in value['elements'])
                lines.append(f"  Call {observation['site']:#x}: Array SP+{value['sp_offset']:#x}, length {value['length']}: {elements}")
        for observation in context['stack_observations']:
            values = ', '.join(f"SP{v['sp_offset']:+d} {v['kind']} {int(v['value'], 16):#x}" for v in observation['values'])
            lines.append(f"  Call {observation['site']:#x}: {values}")
        for resolution in context['resolutions']:
            lines.append(f"  Dispatch {resolution['site']:#x} -> snapshot {resolution['snapshot_target']:#x}")
    lines.append(result['limits'])
    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('graph', type=Path)
    parser.add_argument('--site', required=True, type=lambda value: int(value, 0))
    parser.add_argument('--json', action='store_true')
    args = parser.parse_args()
    try:
        result = query(json.loads(args.graph.read_text()), args.site)
    except (ValueError, KeyError, TypeError) as error:
        parser.error(str(error))
    print(json.dumps(result, indent=2) if args.json else render(result))


if __name__ == '__main__':
    main()
