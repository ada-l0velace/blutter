#!/usr/bin/env python3
"""Show a captured field value restored through an owned local after allocation."""
import argparse
import json
from pathlib import Path
from captured_field_values import SCOPE, note, validate_structure
from graph_io import load_graph
from query_async_fields import query as query_field


def query(graph, site):
    validate_structure(graph)
    rows = []
    for c in graph['captured_field_contexts']:
        field = graph['async_field_contexts'][c['context']]
        access = field['accesses'][c['access']]
        for reload in c['reloads']:
            if reload['site'] != site:continue
            parents = query_field(graph, access['site'])
            assert any(p['seed'] == field['seed'] and p['source_await'] == field['source_await'] and p['class_id'] == field['class_id'] for p in parents), 'Captured value lost its conditional owner source'
            rows.append(dict(site=site, payload=field['payload'], read=access['site'], owner_class=field['class_id'],
                offset=access['offset'], **{k: v for k, v in reload.items() if k != 'site'}, scope=SCOPE, text=note(graph, c, reload)))
    if not rows:raise ValueError('No proven captured field reload at this instruction')
    return rows


def render(rows):
    return '\n'.join(f"{r['site']:#x}: {r['text']}" for r in rows)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('graph', type=Path)
    parser.add_argument('--site', required=True, type=lambda s: int(s, 0))
    parser.add_argument('--json', action='store_true')
    args = parser.parse_args()
    try:rows = query(load_graph(args.graph), args.site)
    except (AssertionError, ValueError, KeyError, IndexError, TypeError, OSError, EOFError) as error:parser.error(str(error))
    print(json.dumps(rows, indent=2) if args.json else render(rows))


if __name__ == '__main__':main()
