"""Package an exported call graph without loading the JSON into memory."""
import gzip
import json
from pathlib import Path
import os
import shutil
import subprocess
import sys
import tempfile


def compress_graph(path):
    path = Path(path)
    destination = path.with_name(path.name + '.gz')
    temporary = None
    try:
        with path.open('rb') as source:
            with tempfile.NamedTemporaryFile(dir=path.parent, prefix='.snapshot_calls-', delete=False) as output:
                temporary = Path(output.name)
                with gzip.GzipFile(filename='', mode='wb', fileobj=output, compresslevel=6, mtime=0) as compressed:
                    shutil.copyfileobj(source, compressed, length=1 << 20)
        os.replace(temporary, destination)
        path.unlink()
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return destination


def run_blutter(command, outdir, compress=False):
    if not compress:
        subprocess.run(command, check=True)
        return
    directory = Path(outdir)
    graph = directory / 'snapshot_calls.json'
    def stamp():
        try:
            stat = graph.stat()
            return stat.st_ino, stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns
        except FileNotFoundError:
            return None
    before = stamp()
    result = subprocess.run(command, check=False)
    # A recoverable analysis error still produces useful exports. Fatal failures
    # may leave an older graph, which must not be repackaged as a new result.
    partial = False
    if compress and result.returncode:
        try:
            partial = json.loads((directory / 'analysis_status.json').read_text())['status'] == 'partial'
        except (OSError, ValueError, KeyError, TypeError):
            pass
    after = stamp()
    if compress and after is not None and after != before and (result.returncode == 0 or partial):
        try:
            compress_graph(graph)
        except OSError as error:
            print(f'Cannot compress snapshot call graph: {error}', file=sys.stderr)
            result.check_returncode()
            raise
    result.check_returncode()
