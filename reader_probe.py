"""Validate a native reader probe against the original application and engine."""
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import tempfile

from elftools.elf.elffile import ELFFile
from elftools.common.exceptions import ELFError

from binary_input import open_binary_input, read_exact
from reader_cache import artifact_hash
from runtime_evidence import collect_guard_evidence, GuardKind, GuardStatus, MAX_LIBRARY_BYTES

PROBE_SCHEMA = 1
MAX_REPORT_BYTES = 64 * 1024


def _require(condition, message):
    if not condition:
        raise RuntimeError('Reader probe rejected: ' + message)


def _integer(report, name):
    value = report.get(name)
    _require(type(value) is int and 0 <= value < 1 << 64, f'invalid {name}')
    return value


def _original_table(path, report, ranges=None):
    with open_binary_input(path, 64, MAX_LIBRARY_BYTES) as (stream, file_size):
        elf = ELFFile(stream)
        _require(elf.elfclass == 64 and elf.little_endian and elf['e_machine'] == 'EM_AARCH64',
                 'unsupported original ELF target')
        segments = [s for s in elf.iter_segments() if s['p_type'] == 'PT_LOAD']
        symbols = elf.get_section_by_name('.dynsym')
        _require(symbols is not None, 'original snapshot symbols missing')

        def symbol(*names):
            for name in names:
                matches = symbols.get_symbol_by_name(name)
                if matches:
                    _require(len(matches) == 1, 'ambiguous original snapshot symbol')
                    return matches[0]
            raise RuntimeError('Reader probe rejected: original snapshot symbol missing')

        def read(address, size):
            _require(type(size) is int and 0 <= size <= MAX_LIBRARY_BYTES, 'invalid original ELF read size')
            for segment in segments:
                base, length, offset = segment['p_vaddr'], segment['p_filesz'], segment['p_offset']
                if base <= address and address + size <= base + length:
                    position = offset + address - base
                    _require(position <= file_size and size <= file_size - position, 'original ELF extent exceeds file')
                    stream.seek(position)
                    return read_exact(stream, size)
            raise RuntimeError('Reader probe rejected: unmapped original ELF extent')

        image = symbol('_kDartSnapshotText', '_kDartIsolateSnapshotInstructions')
        data_symbol = symbol('_kDartSnapshotData', '_kDartIsolateSnapshotData')
        start, data_address = image['st_value'], data_symbol['st_value']
        image_size, section_offset = struct.unpack('<QQ', read(start, 16))
        _require(image_size == image['st_size'] and 128 <= image_size <= MAX_LIBRARY_BYTES and section_offset == 64,
                 'original instructions image header disagrees')
        _require((_integer(report, 'image_start'), _integer(report, 'image_end')) == (start, start + image_size),
                 'reader image boundaries disagree with original ELF')
        header = read(data_address, 0x34)
        _require(header[:4] == b'\xf5\xf5\xdc\xdc', 'invalid original snapshot header')
        snapshot_size = struct.unpack_from('<Q', header, 4)[0] + 4
        _require(0x35 <= snapshot_size <= data_symbol['st_size'], 'invalid original snapshot extent')
        data = read(data_address, min(snapshot_size, 4096))
        try:
            position = data.index(0, 0x34) + 1
        except ValueError as error:
            raise RuntimeError('Reader probe rejected: unterminated snapshot feature string') from error

        def unsigned():
            nonlocal position
            value = 0
            for shift in range(0, 70, 7):
                _require(position < len(data), 'truncated snapshot table header')
                byte = data[position]
                position += 1
                value |= (byte & 0x7f) << shift
                if byte >= 0x80:
                    return value
            raise RuntimeError('Reader probe rejected: oversized snapshot table header integer')

        values = [unsigned() for _ in range(5)]
        table_address = data_address + ((snapshot_size + 63) & ~63) + values[4] + 16
        _require(_integer(report, 'table_address') == table_address, 'reader table location disagrees with original header')
        maps_end, count, first, padding = struct.unpack('<IIII', read(table_address, 16))
        _require(padding == 0 and 0 < count <= image_size // 4 and first <= count,
                 'invalid original native table header')
        _require(count - first == values[3], 'original retained-code count disagrees')
        _require((_integer(report, 'payload_count'), _integer(report, 'first_with_code')) == (count, first),
                 'reader table counts disagree with original header')
        records = list(struct.iter_unpack('<II', read(table_address + 16, count * 8)))
        previous = None
        for pc, stack_map in records:
            _require(section_offset + 40 <= pc < image_size and pc % 4 == 0 and
                     (previous is None or previous < pc), 'invalid original native payload ordering')
            _require(16 + count * 8 <= stack_map < maps_end, 'invalid original stack-map extent')
            previous = pc
        if ranges is not None:
            for index, (pc, _) in enumerate(records):
                ranges[start + pc] = start + (records[index + 1][0] if index + 1 < count else image_size)
        return count


def validate_probe(report, libapp, libflutter, expected_abi="guarded"):
    _require(isinstance(report, dict) and report.get('schema') == PROBE_SCHEMA and
             report.get('status') == 'deserialized', 'invalid native probe report')
    _require(expected_abi in ('guarded', 'guarded_relocations_v1', 'arm64_stub_layout_v1'),
             'unsupported reader ABI proof kind')
    actual_abi = report.get('abi_kind', 'guarded')
    _require(actual_abi == expected_abi, 'unexpected reader ABI proof kind')
    ranges = {} if actual_abi == 'arm64_stub_layout_v1' else None
    count = _original_table(libapp, report, ranges) if ranges is not None else _original_table(libapp, report)
    names = report.get('vm_stubs')
    _require(isinstance(names, list) and 1 <= len(names) <= 4096 and
             all(isinstance(n, str) and re.fullmatch(r'[A-Za-z_][A-Za-z_0-9]{0,127}', n) for n in names) and
             len(set(names)) == len(names), 'invalid ordered VM stub names')
    if actual_abi == 'arm64_stub_layout_v1':
        from reader_stub_evidence import OriginalElf, validate_stub_abi
        proof = validate_stub_abi(report, OriginalElf(libapp), OriginalElf(libflutter), ranges)
        return dict(proof, schema=PROBE_SCHEMA, libapp_sha256=artifact_hash(libapp),
                    libflutter_sha256=artifact_hash(libflutter), payload_count=count,
                    vm_stub_count=len(names), vm_tag_offset=_integer(report, 'vm_tag_offset'))
    blob = b''.join(name.encode('ascii') + b'\0' for name in names)
    with open_binary_input(libflutter, 64, MAX_LIBRARY_BYTES) as (stream, size):
        engine = read_exact(stream, size)
    table = None
    if expected_abi == 'guarded_relocations_v1' or blob not in engine:
        from reader_stub_evidence import OriginalElf, validate_engine_stub_table
        try:
            table = validate_engine_stub_table(OriginalElf(libflutter), names)
        except (ELFError, OSError, ValueError) as error:
            raise RuntimeError('Reader probe rejected: reader VM stub order not found '
                               'in the original engine: ' + str(error)) from error
    guards = collect_guard_evidence(libapp)
    _require(guards.status == GuardStatus.CONSISTENT, f'native guard evidence is {guards.status.value}')
    _require({s.kind for s in guards.observations} == {GuardKind.LEAF, GuardKind.NATIVE},
             'both leaf and native guard forms must be observed')
    state, tag = _integer(report, 'native_call_state_offset'), _integer(report, 'vm_tag_offset')
    _require(state > 0 and tag > 0 and state % 8 == 0 and tag % 8 == 0, 'invalid reader Thread offsets')
    _require(all(s.offsets.state == state and s.offsets.vm_tag == tag for s in guards.observations),
             'reader Thread offsets disagree with original native guards')
    proof = {'schema': PROBE_SCHEMA, 'libapp_sha256': artifact_hash(libapp),
            'libflutter_sha256': artifact_hash(libflutter), 'payload_count': count,
            'vm_stub_count': len(names), 'guard_sites_checked': len(guards.observations),
            'native_call_state_offset': state, 'vm_tag_offset': tag}
    if table is not None:
        proof['engine_stub_table'] = table
    if expected_abi != 'guarded':
        proof['abi_kind'] = expected_abi
    return proof


def _limits():
    import resource
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (16 * 1024 * 1024, 16 * 1024 * 1024))


def run_probe(reader, libapp, libflutter, timeout=120, expected_abi="guarded"):
    with tempfile.TemporaryDirectory(prefix='blutter-reader-probe-') as temporary:
        root = Path(temporary)
        report, output = root / 'probe.json', root / 'output'
        kwargs = {'preexec_fn': _limits} if os.name == 'posix' else {}
        log_path = root / 'probe.log'
        with log_path.open('wb') as log:
            try:
                result = subprocess.run([str(reader), '-i', str(libapp), '-o', str(output),
                                         '--probe-reader', str(report)], stdout=log,
                                        stderr=subprocess.STDOUT, timeout=timeout, **kwargs)
            except subprocess.TimeoutExpired as error:
                raise RuntimeError(f'Reader probe timed out after {timeout} seconds') from error
        if result.returncode:
            with log_path.open('rb') as log:
                log.seek(max(0, log_path.stat().st_size - 4096))
                details = log.read().decode('utf-8', errors='replace')
            raise RuntimeError(f'Reader probe failed with exit code {result.returncode}:\n{details}')
        _require(report.is_file() and report.stat().st_size <= MAX_REPORT_BYTES, 'missing or oversized probe report')
        try:
            status = json.loads((output / 'analysis_status.json').read_text())
            native = json.loads(report.read_text())
        except (OSError, ValueError) as error:
            raise RuntimeError('Reader probe produced invalid completion data') from error
        _require(status == {'status': 'probe_complete', 'analysis_errors': 0}, 'probe did not finish cleanly')
        return validate_probe(native, libapp, libflutter, expected_abi)
