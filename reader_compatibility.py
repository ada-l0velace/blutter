"""Bounded same-format candidates; source evidence is followed by a native probe."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import tempfile

import requests

from reader_profiles import (candidate_profiles, reader_profile, runtime_profile,
                             verify_build_flags, verify_engine_profile)

# Public upstream layout/ABI sources. Equality is deliberately conservative;
# it does not establish equality of unavailable fork sources.
CONTRACT_FILES = (
    'app_snapshot.cc', 'app_snapshot.h', 'object.h', 'raw_object.h', 'class_id.h',
    'thread.h', 'thread.cc', 'stub_code_list.h', 'constants_arm64.h',
    'compiler/stub_code_compiler_arm64.cc', 'compiler/stub_code_compiler.cc',
    'compiler/backend/dart_calling_conventions.cc',
    'compiler/backend/dart_calling_conventions.h', 'compiler/backend/il_arm64.cc',
    'frame_layout.h', 'stack_frame_arm64.h', 'image_snapshot.h',
    'compiler/runtime_offsets_extracted.h', 'object_store.h', 'compiler/runtime_api.h',
)
MAX_SOURCE_BYTES = 8 * 1024 * 1024


@dataclass(frozen=True)
class ReaderSelection:
    profile: str
    observed_version: str
    engine_revision: str
    source_evidence: dict | None = None

    @property
    def needs_probe(self):
        return (self.source_evidence is not None or
                runtime_profile(self.profile).abi_probe != 'guarded')


def _source(cache, repository, revision, path):
    if not re.fullmatch(r'[0-9a-f]{40}', revision):
        raise RuntimeError('Invalid source revision in reader evidence')
    destination = Path(cache) / 'sources' / repository / revision / path
    if destination.is_file():
        if destination.stat().st_size > MAX_SOURCE_BYTES:
            raise RuntimeError('Cached reader evidence exceeds the source size limit')
        return destination.read_bytes()
    url = f'https://raw.githubusercontent.com/{repository}/{revision}/{path}'
    with requests.get(url, stream=True, timeout=(10, 30)) as response:
        response.raise_for_status()
        data = bytearray()
        for chunk in response.iter_content(65536):
            data.extend(chunk)
            if len(data) > MAX_SOURCE_BYTES:
                raise RuntimeError('Reader evidence exceeds the source size limit')
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=destination.parent, delete=False) as stream:
        temporary = Path(stream.name)
        stream.write(data)
    try:
        temporary.replace(destination)
    finally:
        temporary.unlink(missing_ok=True)
    return bytes(data)


def _engine_source(cache, engine_ids, observed_version):
    matches = []
    if not 1 <= len(engine_ids) <= 16:
        raise RuntimeError('Reader candidate requires a bounded set of engine identities')
    identifiers = sorted(set(engine_ids))
    key = hashlib.sha256(json.dumps([observed_version, identifiers]).encode()).hexdigest()
    index = Path(cache) / 'engines' / (key + '.json')
    cached = None
    try:
        if index.stat().st_size <= 4096:
            cached = json.loads(index.read_text())
            if (not isinstance(cached, dict) or cached.get('engine') not in identifiers or
                    not re.fullmatch(r'[0-9a-f]{40}', str(cached.get('base', '')))):
                cached = None
    except (OSError, ValueError):
        pass
    for engine in ([cached['engine']] if cached else identifiers):
        try:
            deps = _source(cache, 'shorebirdtech/flutter', engine, 'DEPS').decode('utf-8')
        except requests.HTTPError as error:
            if error.response is not None and error.response.status_code == 404:
                continue
            raise
        revision = re.findall(r'''['"]dart_revision['"]\s*:\s*['"]([0-9a-f]{40})['"]''', deps)
        if len(revision) != 1:
            continue
        version_source = _source(cache, 'dart-lang/sdk', revision[0], 'tools/VERSION').decode('utf-8')
        fields = dict(re.findall(r'^(CHANNEL|MAJOR|MINOR|PATCH)\s+(\S+)\s*$', version_source, re.M))
        if (fields.get('CHANNEL') == 'stable' and
                '.'.join(fields.get(k, '') for k in ('MAJOR', 'MINOR', 'PATCH')) == observed_version):
            if cached and revision[0] != cached['base']:
                raise RuntimeError('Cached engine evidence disagrees with its pinned dependency')
            matches.append((engine, revision[0]))
    if len(matches) != 1:
        raise RuntimeError('Reader candidate requires one public engine dependency matching the observed Dart version')
    if not cached:
        index.parent.mkdir(parents=True, exist_ok=True)
        index.write_text(json.dumps({'engine': matches[0][0], 'base': matches[0][1]}) + '\n')
    return matches[0]


def _contract(cache, base, candidate_base):
    def compare(path):
        full_path = 'runtime/vm/' + path
        expected = _source(cache, 'dart-lang/sdk', base, full_path)
        actual = _source(cache, 'dart-lang/sdk', candidate_base, full_path)
        if actual != expected:
            raise RuntimeError(f'Reader candidate has a different upstream source contract: {full_path}')
        return {'path': full_path, 'sha256': hashlib.sha256(actual).hexdigest()}
    with ThreadPoolExecutor(max_workers=4) as pool:
        return list(pool.map(compare, CONTRACT_FILES))


def select_reader(version, os_name, arch, compressed, snapshot_hash, engine_ids, flags, cache):
    """Preserve exact registrations; qualify other same-minor/format candidates."""
    exact_error = None
    try:
        exact = reader_profile(version, os_name, arch, compressed, snapshot_hash)
        if exact:
            verify_engine_profile(exact, engine_ids, flags)
            return ReaderSelection(exact, version, runtime_profile(exact).engine)
    except RuntimeError as error:
        exact_error = error
    candidates = candidate_profiles(version, os_name, arch, compressed, snapshot_hash)
    if not candidates:
        if exact_error:
            raise exact_error
        raise RuntimeError(f'Shorebird snapshot format {snapshot_hash} (Dart {version}) has no eligible reader candidate')
    verify_build_flags(flags)
    print('Reader selection: no exact build registration; checking same-format candidates.', flush=True)
    try:
        engine, candidate_base = _engine_source(cache, engine_ids, version)
    except (RuntimeError, requests.RequestException) as error:
        prefix = f'{exact_error}; ' if exact_error else ''
        raise RuntimeError(prefix + f'Candidate source qualification failed: {error}') from error
    failures = []
    for name in candidates:
        profile = runtime_profile(name)
        print(f'Reader candidate: {name} (reader Dart {profile.version}, input Dart {version})', flush=True)
        try:
            evidence = _contract(cache, profile.source_base, candidate_base)
        except RuntimeError as error:
            failures.append(str(error))
            print(f'Reader candidate {name} rejected: {error}', flush=True)
            continue
        return ReaderSelection(name, version, engine, {
            'reader_base': profile.source_base, 'observed_upstream_base': candidate_base,
            'files': evidence,
        })
    raise RuntimeError('No reader candidate passed source qualification: ' + '; '.join(failures))


def write_selection_report(directory, selection, reader_metadata, proof):
    result = {
        'schema': 1, 'status': 'validated_for_input',
        'observed_dart_version': selection.observed_version,
        'engine_revision': selection.engine_revision,
        'reader_profile': selection.profile,
        'reader_dart_version': runtime_profile(selection.profile).version,
        'reader_source_revision': reader_metadata['source_revision'],
        'reader_artifact_sha256': reader_metadata['artifact_sha256'],
        'source_evidence': selection.source_evidence,
        'probe': proof,
        'limits': 'Input-specific structural and target-contract validation; not universal engine or Dart semantic compatibility.',
    }
    path = Path(directory)
    path.mkdir(parents=True, exist_ok=True)
    (path / 'snapshot_reader.json').write_text(json.dumps(result, indent=2) + '\n')
