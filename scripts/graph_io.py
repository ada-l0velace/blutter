"""Read plain or gzip call graphs, keeping evidence requirements explicit."""
import gzip
import json
from pathlib import Path


def require_full_evidence(graph):
    export = graph.get('export')
    if export is not None or graph.get('format', 0) >= 31:
        if not isinstance(export, dict) or export.get('detail') not in ('compact', 'full'):
            raise ValueError('Invalid graph export metadata')
        omitted = [] if export['detail'] == 'full' else ['receiver_blocks', 'call_effect_states']
        if export.get('omitted') != omitted:
            raise ValueError('Invalid graph evidence omissions')
    if export is not None and export['detail'] == 'compact':
        raise ValueError('Full graph evidence required; rerun Blutter with --graph-detail full')


def load_graph(path, *, require_full=False, max_bytes=None):
    path = Path(path)
    if path.is_dir():
        plain = path / 'snapshot_calls.json'
        path = plain if plain.is_file() else path / 'snapshot_calls.json.gz'
    opener = gzip.open if path.suffix == '.gz' else open
    with opener(path, 'rb') as stream:
        if max_bytes is None:
            graph = json.load(stream)
        else:
            data = stream.read(max_bytes + 1)
            if len(data) > max_bytes:
                raise ValueError(f'Graph exceeds {max_bytes >> 20} MiB uncompressed')
            graph = json.loads(data)
    if not isinstance(graph, dict):
        raise ValueError('Call graph must be a JSON object')
    if require_full:
        require_full_evidence(graph)
    return graph
