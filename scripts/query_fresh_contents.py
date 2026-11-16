#!/usr/bin/env python3
"""Explain selected content survival and any separately proved container input."""
import argparse
import json
from pathlib import Path
from graph_io import load_graph
from fresh_content_uses import validate_structure, note


def query(graph, site):
    validate_structure(graph)
    rows = []
    for c in graph['fresh_content_contexts']:
        f = graph['fresh_field_contexts'][c['initialization']]
        if site not in (f['write']['site'], c['transfer']):continue
        rows.append(dict(initialization=f['write']['site'], transfer=c['transfer'], status=c['status'],
            inputs=[note(graph, c, n) for n in c['inputs']]))
    if not rows:raise ValueError('No selected-content context at this instruction')
    return rows


def render(rows):
    return '\n'.join(f"initialization {r['initialization']:#x}: {r['status']}" +
        (f"; transfer {r['transfer']:#x}" if r['transfer'] is not None else '') +
        ''.join('\n  ' + text for text in r['inputs']) for r in rows)


def main():
    p = argparse.ArgumentParser(description=__doc__);p.add_argument('graph', type=Path)
    p.add_argument('--site', required=True, type=lambda s: int(s, 0));p.add_argument('--json', action='store_true')
    args = p.parse_args()
    try:rows = query(load_graph(args.graph), args.site)
    except (AssertionError, ValueError, KeyError, IndexError, TypeError, OSError, EOFError) as e:p.error(str(e))
    print(json.dumps(rows, indent=2) if args.json else render(rows))


if __name__ == '__main__':main()
