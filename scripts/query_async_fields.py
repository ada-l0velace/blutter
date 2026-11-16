#!/usr/bin/env python3
"""Show checked conditional field identities at an original memory instruction."""
import argparse
import json
from pathlib import Path
from graph_io import load_graph
from async_field_accesses import SCOPE, context_key, seeds
from async_future_bindings import CONDITIONS


def query(graph, site):
    admitted = set(seeds(graph))
    layouts = {l['class_id']: l for l in graph.get('async_field_layouts', [])}
    rows = []
    for c in graph.get('async_field_contexts', []):
        for a in c['accesses']:
            if a['site'] != site:
                continue
            if c['scope'] != SCOPE or context_key(c) not in admitted or c['class_id'] not in layouts:
                raise ValueError('Field identity lacks its conditional source or layout')
            field = next((f for f in layouts[c['class_id']]['fields'] if f['offset'] == a['offset']), None)
            rows.append(dict(class_id=c['class_id'], source_await=c['source_await'], seed=c['seed'],
                basis=c['basis'], scope=SCOPE, declaration=field, conditions=list(CONDITIONS) +
                (['normal_call_fallthrough', 'successful_intervening_resumes'] if c['basis'] == 'restored_reference' else []), **a))
    if not rows:
        raise ValueError('No checked field identity at this instruction')
    return rows


def render(rows):
    lines = []
    for r in rows:
        lines += [f"{r['site']:#x}: {r['access']} {r['kind']} at byte {r['offset']:#x} of X{r['base']} class {r['class_id']:#x} [conditional]",
            f"  source await {r['source_await']:#x}; {r['basis']} seed {r['seed']:#x}",
            '  declaration: ' + (json.dumps(r['declaration'], ensure_ascii=False) if r['declaration'] else 'metadata unavailable'),
            '  conditions: ' + ', '.join(r['conditions']),
            '  layout identity only; field value, capture bounds/names and source argument identity remain unproved']
    return '\n'.join(lines)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('graph', type=Path)
    p.add_argument('--site', required=True, type=lambda s: int(s, 0))
    p.add_argument('--json', action='store_true')
    args = p.parse_args()
    try:
        rows = query(load_graph(args.graph), args.site)
    except (ValueError, KeyError, TypeError, OSError, EOFError, AssertionError) as e:
        p.error(str(e))
    print(json.dumps(rows, indent=2) if args.json else render(rows))


if __name__ == '__main__':
    main()
