#!/usr/bin/env python3
"""Show a captured field value written into fresh storage before escape."""
import argparse
import json
from pathlib import Path
from fresh_field_initializations import SCOPE, note, parents, validate_structure
from graph_io import load_graph
from query_captured_fields import query as query_capture


def query(graph, site):
    validate_structure(graph)
    rows = []
    for c in graph['fresh_field_contexts']:
        if not c['write'] or c['write']['site'] != site:continue
        field, access, reload = parents(graph, c)
        assert any(r['read'] == access['site'] and r['owner_class'] == field['class_id'] for r in query_capture(graph, reload['site']))
        rows.append(dict(site=site, payload=field['payload'], kind=c['kind'], destination_class=c['class_id'],
            offset=c['write']['offset'], index=c['write']['index'], length=c['length'], allocation=reload['call'],
            read=access['site'], reload=reload['site'], scope=SCOPE, text=note(graph, c)))
    if not rows:raise ValueError('No proven fresh initialization at this instruction')
    return rows


def render(rows):return '\n'.join(f"{r['site']:#x}: {r['text']}" for r in rows)


def main():
    p = argparse.ArgumentParser(description=__doc__);p.add_argument('graph', type=Path)
    p.add_argument('--site', required=True, type=lambda s: int(s, 0));p.add_argument('--json', action='store_true')
    args = p.parse_args()
    try:rows = query(load_graph(args.graph), args.site)
    except (AssertionError, ValueError, KeyError, IndexError, TypeError, OSError, EOFError) as e:p.error(str(e))
    print(json.dumps(rows, indent=2) if args.json else render(rows))


if __name__ == '__main__':main()
