#!/usr/bin/env python3
"""Show completion operands separately from synchronous returns and await binding.

Use the original-byte/VM audit checker before interpreting these exported facts.
"""
import argparse
import json
from pathlib import Path
from graph_io import load_graph


def query(graph, payload):
    row = next((v for v in graph.get('completion_summaries', []) if v['payload'] == payload), None)
    if row is None:
        raise ValueError('No completion summary for this native payload')
    return row


def render(row):
    lines = [f"Async producer {row['payload']:#x}: {row['status']}"]
    if row['exact_class'] is not None:
        lines.append(f"Successful direct value completions supply heap class {row['exact_class']:#x}.")
    for v in row['completions']:
        value = f"heap class {v['class_id']:#x}" if v['value'] == 'heap_class' else v['value']
        lines.append(f"  {v['site']:#x}: X0 -> {value} [{v['basis']}; {v['operation']}; local normal fallthrough]")
    lines.append(f"Covered entries: {len(row['entries'])}; recorded exits: {len(row['exits'])}.")
    lines.append('Scope: covered payload entries and successful value completions; errors separate. '
                 'No ordinary-return type, Future identity or producer-to-await binding.')
    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('graph', type=Path)
    parser.add_argument('--payload', required=True, type=lambda text: int(text, 0))
    parser.add_argument('--json', action='store_true')
    args = parser.parse_args()
    try:
        row = query(load_graph(args.graph), args.payload)
    except (OSError, EOFError, ValueError, KeyError, TypeError) as error:
        parser.error(str(error))
    print(json.dumps(row, indent=2) if args.json else render(row))


if __name__ == '__main__':
    main()
