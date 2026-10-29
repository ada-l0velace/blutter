#!/usr/bin/env python3
"""Look up a snapshot dispatch target using an analyzed or supplied call index."""
import argparse
import bisect
import json
from pathlib import Path


def query(graph, site, *, index=None, extracted_value=None):
    if index is not None and extracted_value is not None:
        raise ValueError('Supply either an index or an extracted value')
    edges = [edge for edge in graph['edges'] if edge['site'] == site]
    if len(edges) != 1 or edges[0]['via_kind'] != 'dispatch_table':
        raise ValueError('Site must identify one analyzed dispatch transfer')
    edge = edges[0]
    access = edge.get('dispatch')
    table = graph.get('dispatch_table')
    if not access or not table or not table['entries']:
        raise ValueError('Dispatch analysis and snapshot table are required')
    source = 'analyzed_constant'
    if extracted_value is not None:
        expression = access['expression']
        if not expression or not 1 <= expression['width'] <= 32:
            raise ValueError('No supported bitfield expression at this site')
        if not 0 <= extracted_value < 1 << expression['width']:
            raise ValueError('Extracted value exceeds the bitfield width')
        index = extracted_value + expression['addend']
        source = 'supplied_extracted_value'
    elif index is not None:
        source = 'supplied_index'
    else:
        index = access['index']
    if index is None:
        raise ValueError('Index is unknown; supply an observed index or extracted value')
    if not -(1 << 63) <= index < (1 << 63):
        raise ValueError('Index exceeds signed ARM64 range')
    offset = edge['via_offset']
    if offset is None or offset % 8:
        raise ValueError('Dispatch base is not aligned to an entry')
    slot = table['origin'] + offset // 8 + index
    if not 0 <= slot < len(table['entries']):
        raise ValueError('Index is outside the snapshot dispatch table')
    target = table['entries'][slot]
    nodes = graph['nodes']
    starts = [node['start'] for node in nodes]
    if starts != sorted(set(starts)) or any(n['end'] <= n['start'] for n in nodes):
        raise ValueError('Invalid payload inventory')
    pos = bisect.bisect_right(starts, target) - 1 if target is not None else -1
    node = nodes[pos] if pos >= 0 and target < nodes[pos]['end'] else None
    return {'site': site, 'index_source': source, 'extracted_value': extracted_value,
            'index': index, 'table_index': slot, 'snapshot_target': target,
            'null_error_entry': target is not None and target == table['null_target'],
            'payload': node['start'] if node else None, 'label': node['label'] if node else None,
            'limits': 'Snapshot lookup only. Supplied observations and runtime table contents are not verified.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('graph', type=Path)
    parser.add_argument('--site', required=True, type=lambda text: int(text, 0))
    values = parser.add_mutually_exclusive_group()
    values.add_argument('--index', type=lambda text: int(text, 0))
    values.add_argument('--extracted-value', type=lambda text: int(text, 0),
                        help='Observed extracted bitfield value (class ID for a class-ID expression)')
    args = parser.parse_args()
    if args.graph.stat().st_size > 128 << 20:
        parser.error('Graph exceeds 128 MiB')
    try:
        result = query(json.loads(args.graph.read_text()), args.site, index=args.index, extracted_value=args.extracted_value)
    except (ValueError, KeyError, TypeError) as error:
        parser.error(str(error))
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
