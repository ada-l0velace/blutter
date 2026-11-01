"""Source checks and artifact identities for compiled snapshot readers."""
import hashlib
import json
from pathlib import Path
import re
import tempfile
import platform

from runtime_sources import source_snapshot_hash
from reader_profiles import SHOREBIRD_PROFILE, runtime_profile




def profile_patch_hash(profile=SHOREBIRD_PROFILE):
    patch = Path(__file__).resolve().parent / 'scripts' / runtime_profile(profile).patch
    return hashlib.sha256(patch.read_bytes()).hexdigest()


def identity(info, kind, no_analysis=False):
    result = {'version': info.version, 'snapshot_hash': info.snapshot_hash,
              'profile': info.reader_profile, 'os': info.os_name, 'arch': info.arch,
              'compressed_pointers': info.has_compressed_ptrs, 'kind': kind,
              'host_os': platform.system(), 'host_arch': platform.machine()}
    if kind == 'reader':
        result['no_analysis'] = no_analysis
    if info.reader_profile:
        result['runtime_patch_sha256'] = profile_patch_hash(info.reader_profile)
    return result


def artifact_hash(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def metadata_path(path):
    return Path(str(path) + '.reader.json')


def installed_headers_hash(path, info):
    root = Path(path).parent.parent / 'include' / ('dartvm' + info.sdk_key)
    headers = sorted(root.rglob('*.h'))
    if not headers:
        raise OSError('Installed SDK headers are missing')
    digest = hashlib.sha256()
    for header in headers:
        name = header.relative_to(root).as_posix().encode('utf-8')
        digest.update(len(name).to_bytes(8, 'little'))
        digest.update(name)
        digest.update(artifact_hash(header).encode('ascii'))
    return digest.hexdigest()


def read_verified(path, info, kind, no_analysis=False):
    try:
        metadata = metadata_path(path)
        if metadata.stat().st_size > 16384:
            return None
        result = json.loads(metadata.read_text())
        if (not isinstance(result, dict) or result.get('schema') != 1 or
                result.get('identity') != identity(info, kind, no_analysis) or
                not isinstance(result.get('source_revision'), str) or
                not re.fullmatch(r'[0-9a-f]{40}', result['source_revision']) or
                not isinstance(result.get('source_hash'), str) or
                not re.fullmatch(r'[0-9a-f]{32}', result['source_hash']) or
                result.get('artifact_sha256') != artifact_hash(path)):
            return None
        if not info.reader_profile and info.snapshot_hash and result['source_hash'] != info.snapshot_hash:
            return None
        if info.reader_profile and result['source_revision'] != runtime_profile(info.reader_profile).source_base:
            return None
        if kind == 'runtime' and result.get('headers_sha256') != installed_headers_hash(path, info):
            return None
        return result
    except (OSError, ValueError, TypeError):
        return None


def write_verified(path, info, kind, source, no_analysis=False):
    target = metadata_path(path)
    result = {'schema': 1, 'identity': identity(info, kind, no_analysis),
              'source_revision': source['source_revision'], 'source_hash': source['source_hash'],
              'artifact_sha256': artifact_hash(path)}
    if kind == 'runtime':
        result['headers_sha256'] = installed_headers_hash(path, info)
    elif 'headers_sha256' in source:
        result['headers_sha256'] = source['headers_sha256']
    with tempfile.NamedTemporaryFile(mode='w', dir=target.parent, delete=False, encoding='utf-8') as stream:
        temporary = Path(stream.name)
        json.dump(result, stream, indent=2)
        stream.write('\n')
    try:
        temporary.replace(target)
    finally:
        temporary.unlink(missing_ok=True)
    if not read_verified(path, info, kind, no_analysis):
        target.unlink(missing_ok=True)
        raise RuntimeError('Reader artifact failed its identity check after building')


def library_path(info, package_directory, windows=False):
    name = info.lib_name + '.lib' if windows else 'lib' + info.lib_name + '.a'
    return Path(package_directory) / 'lib' / name
