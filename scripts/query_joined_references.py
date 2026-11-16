#!/usr/bin/env python3
"""Show a saved reference with multiple certified last-suspension alternatives."""
import argparse
import json
from pathlib import Path
from graph_io import load_graph
from joined_async_references import validate_structure, note


def query(graph, site=None):
    if graph.get('format', 0) < 46:raise ValueError('Joined references require graph format 46 or newer')
    validate_structure(graph)
    return [dict(payload=c['payload'], source_await=c['source_await'], class_id=c['class_id'], scope=c['scope'], **o, text=note(c, o))
        for c in graph['joined_reference_contexts'] for o in c['observations']
        if site is None or site in (o['site'], c['source_await'], o['store'])]


def render(rows):
    return '\n'.join(f"{r['site']:#x}: {r['text']}" for r in rows) or 'No certified joined reference at this selection'


def main():
    p = argparse.ArgumentParser(description=__doc__);p.add_argument('graph', type=Path)
    p.add_argument('--site', type=lambda s: int(s, 0));p.add_argument('--json', action='store_true')
    a = p.parse_args()
    try:rows = query(load_graph(a.graph), a.site)
    except (AssertionError, ValueError, KeyError, IndexError, TypeError, OSError, EOFError) as e:p.error(str(e) or 'Inconsistent joined-reference certificate')
    print(json.dumps(rows, indent=2) if a.json else render(rows))


if __name__ == '__main__':main()
