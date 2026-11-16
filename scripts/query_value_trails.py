#!/usr/bin/env python3
"""Navigate existing conditional field-value certificates without new inference."""
import argparse
import collections
import json
from pathlib import Path

from graph_io import load_graph
from query_async_fields import query as query_field
from field_input_origins import check_field_inputs, note as input_note, role_proven
from captured_field_values import note as capture_note
from fresh_field_initializations import note as fresh_note
from fresh_content_uses import note as content_note
from callee_entry_reads import validate_structure, note as entry_note

UNPROVED = ['source parameter position/type unless separately certified',
            'later field/element contents or use', 'decision predicate', 'external sink']


def _index(rows, key):
    result = collections.defaultdict(list)
    for n, row in enumerate(rows):result[key(row)].append((n, row))
    return result


def query(graph, site=None, payload=None):
    """Join certificate indices, never instruction proximity or register coincidence.

    As with the individual query tools, certificates must first be verified
    against the matching input bytes/audit by the independent output checkers.
    This view rechecks their structural relations and conditional parent scope.
    """
    if graph.get('format', 0) < 45:
        raise ValueError('Value trails require graph format 45 or newer; regenerate the output')
    validate_structure(graph)
    check_field_inputs(graph)
    fields = graph['async_field_contexts'];origins = graph['call_input_origins']
    if not any(a['access'] == 'read' for c in fields if payload is None or c['payload'] == payload for a in c['accesses']):
        return []
    captures = _index(graph['captured_field_contexts'], lambda c: (c['context'], c['access']))
    fresh = _index(graph['fresh_field_contexts'], lambda f: (f['capture'], f['reload']))
    contents = _index(graph['fresh_content_contexts'], lambda c: c['initialization'])
    consumers = _index(graph['container_entry_read_links'], lambda l: l['context'])
    direct = _index(graph['async_field_input_links'], lambda l: (l['context'], l['access']))
    edges = {e['site']: e for e in graph['edges']}
    shapes = {s['site']: s for s in graph['call_input_shapes']}
    contracts = {s['entry']: s for s in graph['stub_input_contracts']}
    asyncs = {s['entry']: s['operation'] for s in graph['async_contracts']}
    # Resolve conditional parents once per memory site, including shared-site contexts.
    source_rows = {};rows = []
    for ci, context in enumerate(fields):
        if payload is not None and context['payload'] != payload:continue
        for ai, access in enumerate(context['accesses']):
            if access['access'] != 'read':continue
            if access['site'] not in source_rows:source_rows[access['site']] = query_field(graph, access['site'])
            matches = [r for r in source_rows[access['site']] if r['class_id'] == context['class_id'] and
                r['seed'] == context['seed'] and r['source_await'] == context['source_await'] and
                r['basis'] == context['basis'] and r['access'] == 'read' and
                r['base'] == access['base'] and r['offset'] == access['offset'] and
                r['register'] == access['register'] and r['bytes'] == access['bytes']]
            if len(matches) != 1:raise ValueError('Field trail lacks one conditional owner certificate')
            source = matches[0]
            row = dict(context=ci, access=ai, payload=context['payload'], source=source,
                direct_inputs=[], captures=[], unproved=list(UNPROVED))
            sites = {context['payload'], context['source_await'], context['seed'], access['site']}
            for _, link in direct[ci, ai]:
                origin = origins[link['input_origin']]
                row['direct_inputs'].append(dict(transfer=origin['site'], target=edges[origin['site']]['target'],
                    role=origin['role'], index=origin['index'], scope=link['scope'], text=input_note(graph, link)))
                sites.add(origin['site'])
            for capture_index, capture in captures[ci, ai]:
                branch = dict(context=capture_index, status=capture['status'], reloads=[])
                row['captures'].append(branch)
                for ri, reload in enumerate(capture['reloads']):
                    r = dict(reload, text=capture_note(graph, capture, reload), initializations=[])
                    branch['reloads'].append(r);sites.update((reload['site'], reload['store'], reload['call']))
                    for fi, initialization in fresh[capture_index, ri]:
                        f = dict(context=fi, status=initialization['status'], kind=initialization['kind'],
                            write=initialization['write'], contents=[])
                        r['initializations'].append(f)
                        if not initialization['write']:continue
                        f['text'] = fresh_note(graph, initialization);sites.add(initialization['write']['site'])
                        for content_index, content in contents[fi]:
                            c = dict(context=content_index, status=content['status'], transfer=content['transfer'],
                                scope=content['scope'], inputs=[], entry_reads=[])
                            f['contents'].append(c)
                            if content['transfer'] is not None:sites.add(content['transfer'])
                            for oi in content['inputs']:
                                origin = origins[oi]
                                if not role_proven(graph, origin, edges, shapes, contracts, asyncs):
                                    raise ValueError('Container trail has no certified consumer input role')
                                c['inputs'].append(dict(origin=oi, role=origin['role'], index=origin['index'],
                                    text=content_note(graph, content, oi)))
                            for _, link in consumers[content_index]:
                                contract = graph['callee_entry_read_contracts'][link['contract']]
                                read = contract['reads'][link['read']]
                                c['entry_reads'].append(dict(callee=contract['entry'], read=read,
                                    scope=link['scope'], fast_path=contract['guard'] is not None,
                                    text=entry_note(graph, link)))
                                sites.update((contract['entry'], read['site']))
            if site is None or site in sites:rows.append(row)
    return rows


def render(rows, evidence=False):
    if not rows:
        return 'No certified field-value trail matches; this does not establish absence of a decision or external sink'
    lines = []
    for row in rows:
        s = row['source']
        lines += [f"field read {s['site']:#x}: owner class {s['class_id']:#x}, {s['kind']} byte {s['offset']:#x} [conditional]",
            f"  source await {s['source_await']:#x}; {s['basis']} seed {s['seed']:#x}",
            '  conditions: ' + ', '.join(s['conditions'])]
        for i in row['direct_inputs']:
            label = f"supplied input[{i['index']}]" if i['index'] is not None else i['role'].replace('_', ' ')
            lines.append(f"  field input: {label} at transfer {i['transfer']:#x} -> {i['target']:#x} [conditional loaded word only]")
            if evidence:lines.append('    ' + i['text'])
        for capture in row['captures']:
            if not capture['reloads']:lines.append('  capture boundary: ' + capture['status'])
            for r in capture['reloads']:
                lines.append(f"  captured value: save {r['store']:#x} -> FP{r['slot']:+#x} -> allocation {r['call']:#x} -> reload {r['site']:#x} [normal allocation return; captured value only]")
                if evidence:lines.append('    ' + r['text'])
                for f in r['initializations']:
                    if not f['write']:
                        lines.append('  first-write boundary: ' + f['status']);continue
                    w = f['write'];storage = f"array element [{w['index']}]" if w['index'] is not None else f"instance slot {w['offset']:#x}"
                    lines.append(f"  first write: {w['site']:#x} -> {storage} [before escape; first write only]")
                    if evidence:lines.append('    ' + f['text'])
                    for c in f['contents']:
                        if c['transfer'] is None:
                            lines.append(f"  container boundary: {c['status']} [no certified transfer]")
                        else:
                            lines.append(f"  contents: preserved to transfer {c['transfer']:#x} [selected contents at transfer only; normal allocator returns]")
                        for i in c['inputs']:
                            label = f"supplied input[{i['index']}]" if i['index'] is not None else i['role'].replace('_', ' ')
                            lines.append('  container input: ' + label + ' [conditional; later element/field use unknown]')
                            if evidence:lines.append('    ' + i['text'])
                        for e in c['entry_reads']:
                            read = e['read'];condition = '; initial stack-check fast path' if e['fast_path'] else ''
                            lines.append(f"  consumer: callee {e['callee']:#x} reads entry SP+{read['entry_sp_offset']:#x} at {read['site']:#x} [normal producer/allocation returns; successful SDK resumes; value/error-preserving callbacks; incoming stack/heap preserved by checked entry prefix{condition}; selected contents at this read only]")
                            if evidence:lines.append('    ' + e['text'])
        lines += ['  not established by these certificates: ' + '; '.join(row['unproved']), '']
    return '\n'.join(lines).rstrip()


def main():
    p = argparse.ArgumentParser(description=__doc__);p.add_argument('graph', type=Path)
    p.add_argument('--site', type=lambda s: int(s, 0), help='Select any recorded source, write, transfer or callee-read site')
    p.add_argument('--payload', type=lambda s: int(s, 0), help='Select original source payload start')
    p.add_argument('--json', action='store_true');p.add_argument('--evidence', action='store_true', help='Include original certificate note text')
    args = p.parse_args()
    try:rows = query(load_graph(args.graph), args.site, args.payload)
    except (AssertionError, ValueError, KeyError, IndexError, TypeError, OSError, EOFError) as e:
        p.error(str(e) or 'Inconsistent value-trail certificate')
    print(json.dumps(rows, indent=2) if args.json else render(rows, args.evidence))


if __name__ == '__main__':main()
