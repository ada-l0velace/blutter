#!/usr/bin/env python3
"""Show role-proven inputs copied from conditionally identified field reads."""
import argparse
import json
from pathlib import Path
from graph_io import load_graph
from field_input_origins import SCOPE, check_field_inputs, note
from query_async_fields import query as query_field


def query(graph, site):
    check_field_inputs(graph)
    rows = []
    for link in graph.get('async_field_input_links', []):
        o = graph['call_input_origins'][link['input_origin']]
        if o['site'] != site:
            continue
        c = graph['async_field_contexts'][link['context']]
        a = c['accesses'][link['access']]
        # Recheck the delivery and saved-reference parent scopes for navigation.
        source_rows = query_field(graph, a['site'])
        if link['scope'] != SCOPE or not any(r['class_id'] == c['class_id'] and r['seed'] == c['seed'] and r['source_await'] == c['source_await'] for r in source_rows):
            raise ValueError('Field input lacks its conditional owner source')
        rows.append(dict(site=site, payload=o['payload'], role=o['role'], index=o['index'], register=o['register'],
            sp_offset=o['sp_offset'], read=a['site'], owner_class=c['class_id'], offset=a['offset'],
            scope=SCOPE, text=note(graph, link)))
    if not rows:
        raise ValueError('No role-proven field input at this transfer')
    return rows


def render(rows):
    return '\n'.join(f"{r['site']:#x}: {r['text']}" for r in rows)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('graph', type=Path)
    p.add_argument('--site', required=True, type=lambda s: int(s, 0))
    p.add_argument('--json', action='store_true')
    args = p.parse_args()
    try:
        rows = query(load_graph(args.graph), args.site)
    except (AssertionError, ValueError, KeyError, IndexError, TypeError, OSError, EOFError) as e:
        p.error(str(e))
    print(json.dumps(rows, indent=2) if args.json else render(rows))


if __name__ == '__main__':
    main()
