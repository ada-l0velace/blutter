#!/usr/bin/env python3
"""Show direct callers' physical inputs and caller-qualified array results.

This is an index over exported facts, not a verifier or interprocedural solver.
Run check_snapshot_annotations.py with the independent VM audit first.
"""
import argparse
import bisect
import copy
import json
from pathlib import Path


TRACE_COLLECTIONS = ('array_path_contexts', 'array_entry_traces', 'array_result_traces')


def _brief(record, *addresses):
    return {key: hex(value) if key in addresses and value is not None else value
            for key, value in record.items() if key not in ('proof', 'certificate', 'states')}


def _trace_summary(context, collection, describe, effects):
    def returned(claim, relation):
        item = _brief(claim, 'site', 'callee', 'allocation')
        item['callee_info'] = describe(claim['callee'])
        item['effect_collection'], item['callee_relation'] = None, None
        sources = ('call_effects',) if collection == 'array_path_contexts' else ('prefix_call_effects', 'call_effects')
        for source in sources:
            effect = effects[source].get(claim['callee'], {}).get(relation)
            if effect is not None:
                item['effect_collection'], item['callee_relation'] = source, _brief(effect)
                break
        return item

    result = {'collection': collection, 'payload': hex(context['payload']),
              'scope': context['scope'], 'status': context['status'],
              'inputs': [_brief(v) for v in context.get('inputs', [])],
              'array_input': copy.deepcopy(context['array_input']),
              'path_condition': None, 'trace': None,
              'reads': [_brief(v, 'site') for v in context.get('array_reads', [])],
              'length_returns': [returned(v, 'array_length') for v in context.get('array_length_returns', [])],
              'indexed_returns': [returned(v, 'array_return') for v in context.get('indexed_returns', [])],
              'dispatches': [dict(_brief(v, 'site', 'load', 'snapshot_target'),
                                  target_info=describe(v['snapshot_target'])) for v in context['resolutions']]}
    if context.get('path_condition') is not None:
        result['path_condition'] = _brief(context['path_condition'], 'site', 'successor', 'slow_path', 'stub')
    if context.get('trace') is not None:
        trace = context['trace']
        result['trace'] = dict(_brief(trace, 'getter', 'stop'),
                               blocks=[hex(v) for v in trace['blocks']],
                               stack_checks=[_brief(v, 'site', 'successor', 'slow_path', 'stub')
                                             for v in trace['stack_checks']])
    return result


def query(graph, target, limit=20, *, caller=None):
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
    selected_callers = callers if caller is None else [e for e in callers if e['site'] == caller]
    if caller is not None and (type(caller) is not int or not selected_callers):
        raise ValueError('caller must identify a direct call instruction to the selected target')
    shown_callers = selected_callers[:limit]
    ordered_nodes = sorted(nodes.values(), key=lambda n: n['start'])
    starts = [n['start'] for n in ordered_nodes]
    descriptions = {}

    def describe(address):
        if address not in descriptions:
            pos = bisect.bisect_right(starts, address)-1
            container = ordered_nodes[pos] if pos >= 0 and address < ordered_nodes[pos]['end'] else None
            descriptions[address] = {'entry': hex(address),
                                     'containing_payload': hex(container['start']) if container else None,
                                     'payload_label': container['label'] if container else None,
                                     'entry_names': [{k: n[k] for k in ('kind', 'name')}
                                                     for n in container.get('names', []) if n['address'] == address]
                                                    if container else []}
        return descriptions[address]

    effects = {source: {v['payload']: v for v in graph.get(source, [])}
               for source in ('call_effects', 'prefix_call_effects')}
    direct_sites, visible_sites = {e['site'] for e in callers}, {e['site'] for e in shown_callers}
    traces_by_caller, traced_callers = {}, set()
    trace_counts = dict.fromkeys(TRACE_COLLECTIONS, 0)
    for collection in TRACE_COLLECTIONS:
        for context in graph.get(collection, []):
            if context['payload'] != target:
                continue
            linked = direct_sites.intersection(context['callers'])
            if not linked:
                continue
            trace_counts[collection] += 1
            traced_callers.update(linked)
            visible = linked & visible_sites
            if visible:
                item = _trace_summary(context, collection, describe, effects)
                for site in visible:
                    traces_by_caller.setdefault(site, []).append(item)
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
        for caller_site in context['callers']:
            context_by_caller[caller_site] = resolutions
            returns_by_caller[caller_site] = [dict(v, site=hex(v['site']), callee=hex(v['callee']))
                                         for v in context.get('forwarded_returns', [])]
    arrays_by_caller = {}
    selected_arrays = [c for c in graph.get('array_contexts', []) if c['payload'] == target]
    for context in selected_arrays:
        item = {k: context[k] for k in ('array_input', 'scope', 'status')}
        item['reads'] = [dict(v, site=hex(v['site'])) for v in context['array_reads']]
        item['dispatches'] = [dict(v, site=hex(v['site']), load=hex(v['load']), snapshot_target=hex(v['snapshot_target'])) for v in context['resolutions']]
        for caller_site in context['callers']:
            arrays_by_caller.setdefault(caller_site, []).append(item)
    calls = []
    for edge in shown_callers:
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
                      'indexed_return': edge.get('indexed_return'),
                      'array_contexts': arrays_by_caller.get(edge['site'], []),
                      'array_traces': traces_by_caller.get(edge['site'], []),
                      'array_arguments': [dict(v, allocation=hex(v['allocation'])) for v in edge.get('array_arguments', [])],
                      'context_forwarded_returns': returns_by_caller.get(edge['site'], [])})
    effect = next((c for c in graph.get('call_effects', []) if c['payload'] == target), {})
    result_forwarding = ({'register': graph['receiver_metadata']['word_return_register'],
                          'input_sp_offset': effect['return_input']} if effect.get('return_input') is not None else None)
    return {'target': hex(target), 'target_label': node['label'],
            'mapping_available': target == node['start'], 'caller_count': len(callers),
            'caller_filter': hex(caller) if caller is not None else None,
            'selected_caller_count': len(selected_callers), 'shown_caller_count': len(calls),
            'array_trace_counts': trace_counts, 'callers_with_array_traces': len(traced_callers),
            'callers_with_observations': sum(bool(e.get('stack_inputs')) for e in callers),
            'callers_with_context_dispatches': sum(bool(v) for v in context_by_caller.values()),
            'callers_with_context_forwarded_returns': sum(bool(v) for v in returns_by_caller.values()),
            'callers_with_array_arguments': sum(bool(e.get('array_arguments')) for e in callers),
            'array_context_count': len(selected_arrays),
            'callers_with_array_contexts': len(arrays_by_caller),
            'array_context_reads': sum(len(c['array_reads']) for c in selected_arrays),
            'array_result': {k: v for k, v in effect['array_return'].items() if k != 'states'} if effect.get('array_return') else None,
            'result_forwarding': result_forwarding, 'calls': calls,
            'limits': 'Partial recent stores and physical entry-stack loads only. A matched slot does not establish '
                      'a complete parameter list. result_forwarding is a checked physical word relation, '
                      'not a source return type. array_arguments are partial proved element classes at the call boundary; '
                      'array_contexts separately bind selected inputs and may prove entry-block reads. bound_only establishes supplied contents, not a callee read or effects. context_dispatches and context_forwarded_returns are separate bounded '
                      'caller-specific analyses; the query itself does not solve or verify them. Interior-entry '
                      'calls have no payload-entry SP mapping. array_traces retain their source collection, caller '
                      'inputs and path/stop conditions; they never add a global signature or unconditional target. '
                      'Their helper relations are conditional on the supplied inputs and normal return. Payload '
                      'labels may cover shared bodies; entry_names list metadata at the exact target. Counts cover '
                      'all direct callers of the target; the caller filter and display limit affect calls only. '
                      'Omitted callers/slots are unknown.'}


def render_text(result):
    """Compact view of recorded inputs and traces; JSON retains the full query."""
    lines = [f"Target {result['target']} (payload label: {result['target_label']})",
             f"Direct callers: {result['caller_count']}; selected: {result['selected_caller_count']}; shown: {result['shown_caller_count']}",
             'Recorded trace counts for this target: '+', '.join(f'{k}={v}' for k, v in result['array_trace_counts'].items()),
             'Stack slots use the recorded Dart entry-stack offsets.']

    def helper(item):
        info, relation = item['callee_info'], item['callee_relation']
        line = f"      Helper entry {info['entry']}; containing payload {info['containing_payload'] or 'unknown'}; effect collection {item['effect_collection'] or 'unavailable'}"
        lines.append(line)
        if relation is not None:
            slots = [f"{key}={relation[key]:+d}" for key in ('array_sp_offset', 'index_sp_offset') if key in relation]
            lines.append('      Physical helper slots: '+', '.join(slots))

    for call in result['calls']:
        lines += ['', f"Caller {call['site']} in {call['source']} ({call['source_label']})"]
        for value in call['stack_inputs']:
            lines.append(f"  Input SP{value['sp_offset']:+d}: {value['kind']}={value['value']}")
        for context in call['array_contexts']:
            lines.append(f"  Ordinary array context: {context['scope']} / {context['status']}")
        if not call['array_traces']:
            lines.append('  Scoped array traces: none recorded')
        for context in call['array_traces']:
            lines.append(f"  [{context['collection']}] {context['scope']} / {context['status']}")
            inputs = ', '.join(f"SP{v['sp_offset']:+d} {v['kind']}={v['value']}" for v in context['inputs'])
            lines.append('    Input conditions: '+(inputs or 'none recorded'))
            array = context['array_input']
            elements = ', '.join(f'[{index}]=class {cid}' for index, cid in array['elements'])
            lines.append(f"    Array at entry SP{array['sp_offset']:+d}: length={array['length']}; known elements: {elements or 'none recorded'}")
            path = context['path_condition']
            if path:
                lines.append(f"    Initial stack condition: {path['edge']} at {path['site']}; slow stub {path['stub']}")
            trace = context['trace']
            if trace:
                lines.append(f"    Trace: {len(trace['blocks'])} blocks; stops at {trace['stop']}")
                for guard in trace['stack_checks']:
                    lines.append(f"    Additional stack condition: {guard['edge']} at {guard['site']}; slow stub {guard['stub']}")
            for item in context['length_returns']:
                lines.append(f"    Length call {item['site']}: {item['register']}={item['value']} (tagged); length={item['length']}")
                helper(item)
            for item in context['reads']:
                lines.append(f"    Array read {item['site']}: index={item['index']} -> {item['register']} class {item['class_id']}")
            for item in context['indexed_returns']:
                lines.append(f"    Getter {item['site']}: index={item['index']} -> {item['register']} class {item['class_id']} on normal return")
                helper(item)
            for item in context['dispatches']:
                info = item['target_info']
                lines.append(f"    Dispatch {item['site']} -> {item['snapshot_target']} (containing payload {info['containing_payload'] or 'unknown'})")
                if info['entry_names']:
                    lines.append('      Metadata entry names: '+'; '.join(f"{n['kind']}: {n['name']}" for n in info['entry_names']))
                elif info['payload_label']:
                    lines.append('      Payload label: '+info['payload_label'])
    lines += ['', 'Recorded caller/path conditions apply. The query does not verify proofs or infer complete source types.']
    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('graph', type=Path, help='snapshot_calls.json')
    parser.add_argument('--target', type=lambda s: int(s, 0), required=True, help='ELF VA of the direct call destination')
    parser.add_argument('--limit', type=int, default=20, help='Maximum callers displayed (1..1000)')
    parser.add_argument('--caller', type=lambda s: int(s, 0), help='ELF address of one direct call instruction to the target')
    parser.add_argument('--format', choices=('json', 'text'), default='json', help='Output format (default: json)')
    args = parser.parse_args()
    try:
        result = query(json.loads(args.graph.read_text()), args.target, args.limit, caller=args.caller)
        output = json.dumps(result, indent=2) if args.format == 'json' else render_text(result)
    except (OSError, ValueError, KeyError, TypeError) as error:
        parser.error(str(error))
    print(output)


if __name__ == '__main__':
    main()
