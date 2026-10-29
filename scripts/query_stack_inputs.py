#!/usr/bin/env python3
"""Join direct callers' physical stack observations to payload-entry loads.

This is an index over exported facts, not a verifier or interprocedural solver.
Run check_snapshot_annotations.py with the independent VM audit first.
"""
import argparse
import json
from pathlib import Path


def query(graph, target, limit=20):
    if graph.get('format', 0) < 5:
        raise ValueError('Stack observations require snapshot_calls format 5 or later')
    if not 1 <= limit <= 1000:
        raise ValueError('limit must be between 1 and 1000')
    nodes = {n['start']: n for n in graph['nodes']}
    node = next((n for n in nodes.values() if n['start'] <= target < n['end']), None)
    if node is None:
        raise ValueError('Target is outside the payload inventory')
    # Only an exact payload entry establishes the same entry-SP coordinate.
    loads = [v for v in graph.get('entry_stack_loads', []) if v['payload'] == target]
    callers = [e for e in graph['edges'] if e['kind'] == 'call' and e['target'] == target]
    context_by_caller = {}
    returns_by_caller = {}
    for context in graph.get('call_contexts', []):
        if context['payload'] != target:
            continue
        resolutions = []
        for resolution in context['resolutions']:
            label = next((n['label'] for n in nodes.values() if n['start'] <= resolution['snapshot_target'] < n['end']), '')
            resolutions.append(dict(resolution, site=hex(resolution['site']), load=hex(resolution['load']),
                                    snapshot_target=hex(resolution['snapshot_target']), snapshot_target_label=label))
        for caller in context['callers']:
            context_by_caller[caller] = resolutions
            returns_by_caller[caller] = [dict(v, site=hex(v['site']), callee=hex(v['callee']))
                                         for v in context.get('forwarded_returns', [])]
    calls = []
    for edge in callers[:limit]:
        values = []
        for item in edge.get('stack_inputs', []):
            value = dict(item)
            # A 4-byte read is shown as an overlapping physical read; the full
            # stored heap-pointer class cannot be assigned to a narrowed load.
            value['callee_loads'] = [dict(v, site=hex(v['site']), payload=hex(v['payload']))
                                     for v in loads if v['entry_sp_offset'] == item['sp_offset']]
            values.append(value)
        calls.append({'site': hex(edge['site']), 'source': hex(edge['source']),
                      'source_label': nodes.get(edge['source'], {}).get('label', ''), 'stack_inputs': values,
                      'context_dispatches': context_by_caller.get(edge['site'], []),
                      'forwarded_return': edge.get('forwarded_return'),
                      'context_forwarded_returns': returns_by_caller.get(edge['site'], [])})
    effect = next((c for c in graph.get('call_effects', []) if c['payload'] == target), {})
    result_forwarding = ({'register': graph['receiver_metadata']['word_return_register'],
                          'input_sp_offset': effect['return_input']} if effect.get('return_input') is not None else None)
    return {'target': hex(target), 'target_label': node['label'],
            'mapping_available': target == node['start'], 'caller_count': len(callers),
            'callers_with_observations': sum(bool(e.get('stack_inputs')) for e in callers),
            'callers_with_context_dispatches': sum(bool(v) for v in context_by_caller.values()),
            'callers_with_context_forwarded_returns': sum(bool(v) for v in returns_by_caller.values()),
            'result_forwarding': result_forwarding, 'calls': calls,
            'limits': 'Partial recent stores and physical entry-stack loads only. A matched slot does not establish '
                      'a complete parameter list. result_forwarding is a checked physical word relation, '
                      'not a source return type. context_dispatches and context_forwarded_returns are separate bounded '
                      'caller-specific analyses; the query itself does not solve or verify them. Interior-entry '
                      'calls have no payload-entry SP mapping. Omitted callers/slots are unknown.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('graph', type=Path, help='snapshot_calls.json')
    parser.add_argument('--target', type=lambda s: int(s, 0), required=True, help='ELF VA of the direct call destination')
    parser.add_argument('--limit', type=int, default=20, help='Maximum callers displayed (1..1000)')
    args = parser.parse_args()
    try:
        result = query(json.loads(args.graph.read_text()), args.target, args.limit)
    except (OSError, ValueError, KeyError, TypeError) as error:
        parser.error(str(error))
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
