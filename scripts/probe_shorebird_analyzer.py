#!/usr/bin/env python3
"""Run a supplied macOS snapshot analyzer and summarize its JSON for review."""
import argparse
from collections import Counter
from contextlib import contextmanager
import hashlib
import json
import math
import os
from pathlib import Path
import selectors
import signal
import stat
import subprocess
import sys
import time

MAX_ANALYZER_BYTES = 128 * 1024 * 1024
MAX_INPUT_BYTES = 1024 * 1024 * 1024
MAX_JSON_BYTES = 64 * 1024 * 1024
MAX_LOG_BYTES = 8 * 1024 * 1024
MAX_JSON_DEPTH = 64
MAX_JSON_ITEMS = 2000000
MAX_OBJECTS = 250000
MACH_MAGICS = (b'\xcf\xfa\xed\xfe', b'\xfe\xed\xfa\xcf',
               b'\xca\xfe\xba\xbe', b'\xbe\xba\xfe\xca',
               b'\xca\xfe\xba\xbf', b'\xbf\xba\xfe\xca')
LIMITS = ('This is a metadata probe, not a sandbox or a Blutter importer. '
          'Code ranges and host/target layouts have not been verified.')


class ProbeError(ValueError):
    pass


@contextmanager
def open_regular(path, maximum):
    flags = os.O_RDONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NONBLOCK', 0) | getattr(os, 'O_NOFOLLOW', 0)
    descriptor = os.open(path, flags)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= maximum:
            raise ProbeError('Expected a nonempty regular file within the size limit')
        with os.fdopen(descriptor, 'rb') as stream:
            descriptor = None
            yield stream
    finally:
        if descriptor is not None:
            os.close(descriptor)


def fingerprint(stream, maximum):
    before = os.fstat(stream.fileno())
    if not 0 < before.st_size <= maximum:
        raise ProbeError('Input size changed or exceeds the probe limit')
    stream.seek(0)
    digest = hashlib.sha256()
    remaining = before.st_size
    while remaining:
        data = stream.read(min(65536, remaining))
        if not data:
            raise ProbeError('Input changed while being read')
        digest.update(data)
        remaining -= len(data)
    after = os.fstat(stream.fileno())
    if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        raise ProbeError('Input changed while being read')
    return digest.hexdigest()


def check_json_budget(raw):
    depth = items = 0
    quoted = escaped = False
    for byte in raw:
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
        elif byte in (123, 91):
            depth += 1
            items += 1
            if depth > MAX_JSON_DEPTH:
                raise ProbeError('JSON nesting exceeds the probe limit')
        elif byte in (125, 93):
            depth -= 1
            if depth < 0:
                raise ProbeError('Invalid JSON nesting')
        elif byte in (44, 58):
            items += 1
        if items > MAX_JSON_ITEMS:
            raise ProbeError('JSON item count exceeds the probe limit')


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ProbeError('Duplicate JSON key')
        result[key] = value
    return result


def json_integer(text):
    if len(text) > 21:
        raise ProbeError('JSON integer exceeds the probe limit')
    value = int(text)
    if not -(1 << 63) <= value < 1 << 64:
        raise ProbeError('JSON integer exceeds the probe limit')
    return value


def json_float(text):
    if len(text) > 128:
        raise ProbeError('JSON number exceeds the probe limit')
    value = float(text)
    if not math.isfinite(value):
        raise ProbeError('Nonfinite JSON number')
    return value


def reject_constant(_):
    raise ProbeError('Nonstandard JSON numeric constant')


def unsigned(value):
    return type(value) is int and 0 <= value < 1 << 64


def summarize_document(document):
    if not isinstance(document, dict):
        raise ProbeError('Unsupported JSON root; raw output retained for review')
    objects, metadata = document.get('objects'), document.get('metadata')
    if not isinstance(objects, list) or not objects or len(objects) > MAX_OBJECTS:
        raise ProbeError('Missing or oversized object list; raw output retained for review')
    if not isinstance(metadata, dict):
        raise ProbeError('Missing analyzer metadata; raw output retained for review')
    word = metadata.get('word_size')
    compressed = metadata.get('compressed_word_size')
    version = metadata.get('analyzer_version')
    if (not unsigned(word) or word not in (4, 8) or not unsigned(compressed) or
            compressed not in (4, 8) or compressed > word or not unsigned(version) or not version):
        raise ProbeError('Unsupported analyzer metadata; raw output retained for review')
    counts = Counter()
    ids = set()
    capabilities = dict.fromkeys(('classes', 'class_slots', 'field_types', 'function_signatures',
                                 'code_ranges', 'object_pools', 'strings'), False)
    known = {'Library', 'Class', 'Field', 'Function', 'Code', 'ObjectPool',
             'String', 'Type', 'Array', 'Instance', 'Null', 'NoValue'}
    for row in objects:
        if not isinstance(row, dict):
            raise ProbeError('Object records must be JSON objects')
        if 'id' in row:
            identity = row['id']
            if not unsigned(identity) or not identity or identity in ids:
                raise ProbeError('Invalid or duplicate object ID')
            ids.add(identity)
        kind = row.get('type')
        if kind is not None and not isinstance(kind, str):
            raise ProbeError('Object type must be a string')
        counts[kind if kind in known else 'other'] += 1
        if kind == 'Class':
            capabilities['classes'] |= isinstance(row.get('name'), str)
            capabilities['class_slots'] |= isinstance(row.get('instance_slots'), list)
        elif kind == 'Field':
            capabilities['field_types'] |= unsigned(row.get('type_class'))
        elif kind == 'Function':
            capabilities['function_signatures'] |= isinstance(row.get('signature'), str)
        elif kind == 'Code':
            offset, size = row.get('offset'), row.get('size')
            if not unsigned(offset) or not unsigned(size) or size > (1 << 64) - 1 - offset:
                raise ProbeError('Invalid code range')
            capabilities['code_ranges'] |= size > 0 and isinstance(row.get('section'), str)
        elif kind == 'ObjectPool':
            references = row.get('references')
            if not isinstance(references, list) or len(references) % 3 or not all(map(unsigned, references)):
                raise ProbeError('Unsupported object-pool reference triples')
            capabilities['object_pools'] |= bool(references)
        elif kind == 'String':
            capabilities['strings'] |= isinstance(row.get('value'), str)
    return {'status': 'exported_for_review', 'objects': len(objects), 'counts': dict(sorted(counts.items())),
            'analyzer_version': version, 'word_size': word, 'compressed_word_size': compressed,
            'observed_metadata': capabilities, 'limits': LIMITS}


def summarize_json(path):
    with open_regular(path, MAX_JSON_BYTES) as stream:
        raw = stream.read(MAX_JSON_BYTES + 1)
    if len(raw) > MAX_JSON_BYTES:
        raise ProbeError('JSON output exceeds the probe limit')
    check_json_budget(raw)
    try:
        document = json.loads(raw.decode('utf-8'), object_pairs_hook=unique_object,
                              parse_int=json_integer, parse_float=json_float, parse_constant=reject_constant)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise ProbeError('Invalid analyzer JSON; raw output retained for review') from error
    return summarize_document(document)


def check_snapshot_file(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode):
        raise ProbeError('Analyzer output is not a regular file')
    if info.st_size > MAX_JSON_BYTES:
        raise ProbeError('JSON output exceeds the probe limit')


def kill_group(process):
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def run_analyzer(command, output, timeout):
    snapshot = output / 'snapshot.json'
    descriptor = os.open(snapshot, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(descriptor)
    descriptor = os.open(output / 'analyzer.log', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, 'wb', buffering=0) as log:
        return capture_process(command, output, timeout, log)


def capture_process(command, output, timeout, log):
    snapshot = output / 'snapshot.json'
    environment = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LANG': 'C', 'LC_ALL': 'C'}
    process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, cwd=output, env=environment,
                               shell=False, start_new_session=True, close_fds=True)
    selector = None
    started = time.monotonic()
    size = 0
    eof = descendants_stopped = False
    try:
        selector = selectors.DefaultSelector()
        os.set_blocking(process.stdout.fileno(), False)
        selector.register(process.stdout, selectors.EVENT_READ)
        while True:
            if time.monotonic() - started >= timeout:
                raise ProbeError('Analyzer timed out; partial output and log retained')
            check_snapshot_file(snapshot)
            for key, _ in selector.select(0.05):
                data = os.read(key.fd, 65536)
                if data:
                    available = MAX_LOG_BYTES - size
                    log.write(data[:available])
                    size += len(data)
                    if size > MAX_LOG_BYTES:
                        raise ProbeError('Analyzer log exceeds the probe limit')
                else:
                    eof = True
                    selector.unregister(process.stdout)
            returncode = process.poll()
            if returncode is not None:
                if not descendants_stopped:
                    kill_group(process)
                    descendants_stopped = True
                if eof:
                    check_snapshot_file(snapshot)
                    return returncode
    finally:
        if selector is not None:
            selector.close()
        process.stdout.close()
        kill_group(process)
        process.wait(timeout=5)


def probe(analyzer, library, output, timeout=120):
    if sys.platform != 'darwin':
        raise ProbeError('The vendor probe runs only on macOS; no analyzer was started')
    if not math.isfinite(timeout) or not 1 <= timeout <= 3600:
        raise ProbeError('Timeout must be between 1 and 3600 seconds')
    analyzer = Path(os.path.abspath(analyzer))
    library = Path(os.path.abspath(library))
    requested = Path(os.path.abspath(output))
    output = requested.parent.resolve(strict=True) / requested.name
    with open_regular(analyzer, MAX_ANALYZER_BYTES) as executable, open_regular(library, MAX_INPUT_BYTES) as source:
        if os.path.samefile(analyzer, library):
            raise ProbeError('Analyzer and input must be different files')
        if executable.read(4) not in MACH_MAGICS or not os.access(analyzer, os.X_OK):
            raise ProbeError('Supply an executable macOS Mach-O analyzer; permissions were not changed')
        if source.read(4) != b'\x7fELF':
            raise ProbeError('This probe accepts an extracted ELF library, not an APK or archive')
        analyzer_digest = fingerprint(executable, MAX_ANALYZER_BYTES)
        input_digest = fingerprint(source, MAX_INPUT_BYTES)
        output.mkdir(mode=0o700)
        command = [str(analyzer), '--out=snapshot.json', str(library)]
        try:
            returncode = run_analyzer(command, output, timeout)
        finally:
            for path, stream, expected, limit in ((analyzer, executable, analyzer_digest, MAX_ANALYZER_BYTES),
                                                   (library, source, input_digest, MAX_INPUT_BYTES)):
                if not os.path.samestat(os.stat(path, follow_symlinks=False), os.fstat(stream.fileno())) or fingerprint(stream, limit) != expected:
                    raise ProbeError('Analyzer or input changed during the probe')
        if returncode:
            raise ProbeError(f'Analyzer exited with status {returncode}; inspect analyzer.log')
        result = summarize_json(output / 'snapshot.json')
        result.update(analyzer_sha256=analyzer_digest, input_sha256=input_digest)
        return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--analyzer', type=Path, required=True)
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True, help='New directory under an existing parent')
    parser.add_argument('--timeout', type=float, default=120, help='Time limit in seconds (default: 120)')
    args = parser.parse_args(argv)
    try:
        print('Vendor probe: starting; diagnostics will be saved in analyzer.log.', flush=True)
        result = probe(args.analyzer, args.input, args.output, args.timeout)
    except ProbeError as error:
        print(f'probe failed: {error}', file=sys.stderr)
        return 1
    except (OSError, subprocess.SubprocessError) as error:
        print(f'probe failed: {type(error).__name__}; check paths, permissions and analyzer.log if created', file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print('probe interrupted; partial output retained', file=sys.stderr)
        return 130
    print(json.dumps(result, indent=2, ensure_ascii=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
