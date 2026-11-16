#!/usr/bin/env python3
"""Show byte-checked callee-entry stack reads of selected container contents."""
import argparse
import json
from pathlib import Path
from graph_io import load_graph
from callee_entry_reads import validate_structure, note


def query(graph, site):
    validate_structure(graph)
    rows = []
    for l in graph['container_entry_read_links']:
        c = graph['fresh_content_contexts'][l['context']];f = graph['fresh_field_contexts'][c['initialization']]
        contract = graph['callee_entry_read_contracts'][l['contract']];r = contract['reads'][l['read']]
        if site in (c['transfer'], f['write']['site'], r['site']):
            rows.append(dict(transfer=c['transfer'], callee=contract['entry'], read=r, note=note(graph, l)))
    return rows


def render(rows):
    return '\n'.join(f"transfer {r['transfer']:#x} -> callee {r['callee']:#x}\n  {r['note']}" for r in rows) or 'No role-proven container entry read at this instruction'


def main():
    p = argparse.ArgumentParser(description=__doc__);p.add_argument('graph', type=Path)
    p.add_argument('--site', required=True, type=lambda s: int(s, 0));p.add_argument('--json', action='store_true')
    args = p.parse_args()
    try:rows = query(load_graph(args.graph), args.site)
    except (AssertionError, ValueError, KeyError, IndexError, TypeError, OSError, EOFError) as e:p.error(str(e))
    print(json.dumps(rows, indent=2) if args.json else render(rows))


if __name__ == '__main__':main()
