#!/usr/bin/env python3
"""Compare snapshot source identities without building or executing a reader."""

import argparse
from concurrent.futures import ThreadPoolExecutor
import contextlib
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import sys
import tempfile

import requests

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from runtime_sources import SourceRecipeError as ProbeError, snapshot_files
LIMITS = ('A source-hash match is a candidate identity, not proof of target layout, '
          'successful deserialization or complete analysis. This command does not '
          'modify readers, SDK packages or input libraries. A source mismatch does '
          'not rule out a separately verified adapted reader.')
REPOSITORY = re.compile(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z')
REFERENCE = re.compile(r'(?:[0-9a-f]{40}|[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?)\Z')
SHA = re.compile(r'[0-9a-f]{40}\Z')
MAX_FILE_BYTES = 16 * 1024 * 1024




class Sources:
    def __init__(self, cache, offline=False, refresh=False):
        if offline and refresh:
            raise ProbeError('Offline probing cannot refresh source metadata')
        self.cache = Path(cache).resolve()
        self.offline = offline
        self.refresh = refresh

    def location(self, relative):
        path = self.cache.joinpath(*PurePosixPath(relative).parts)
        if not path.resolve().is_relative_to(self.cache):
            raise ProbeError('Source cache path escapes its root')
        return path

    @staticmethod
    def download(url):
        with requests.get(url, stream=True, timeout=(10, 30)) as response:
            response.raise_for_status()
            chunks, size = [], 0
            for chunk in response.iter_content(64 * 1024):
                size += len(chunk)
                if size > MAX_FILE_BYTES:
                    raise ProbeError('Source response exceeds the download limit')
                chunks.append(chunk)
            return b''.join(chunks)

    def read(self, relative, url, refresh=False):
        path = self.location(relative)
        if path.exists() and not refresh:
            if path.stat().st_size > MAX_FILE_BYTES:
                raise ProbeError('Cached source exceeds the size limit')
            return path.read_bytes()
        if self.offline:
            raise ProbeError(f'Source is not cached for offline use: {relative}')
        data = self.download(url)
        path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as temporary:
            temporary.write(data)
            staged = Path(temporary.name)
        try:
            staged.replace(path)
        finally:
            staged.unlink(missing_ok=True)
        return data

    def resolve(self, repository, reference):
        if not REPOSITORY.fullmatch(repository) or not REFERENCE.fullmatch(reference):
            raise ProbeError('Use a GitHub owner/repository and a release tag or full commit')
        if SHA.fullmatch(reference):
            return reference
        url = f'https://api.github.com/repos/{repository}/commits/{reference}'
        data = self.read(f'{repository}/resolutions/{reference}.json', url, self.refresh)
        try:
            revision = json.loads(data)['sha']
        except (ValueError, KeyError, TypeError) as error:
            raise ProbeError('Invalid source revision response') from error
        if not isinstance(revision, str) or not SHA.fullmatch(revision):
            raise ProbeError('Source did not resolve to a full commit')
        return revision

    def releases(self, series):
        if not re.fullmatch(r'[0-9]+\.[0-9]+', series):
            raise ProbeError('Use major.minor for a release series')
        repository = 'dart-lang/sdk'
        url = f'https://api.github.com/repos/{repository}/git/matching-refs/tags/{series}.'
        try:
            rows = json.loads(self.read(f'{repository}/releases/{series}.json', url, self.refresh))
            if not isinstance(rows, list):
                raise ValueError('expected release references')
            prefix = f'refs/tags/{series}.'
            tags = {row['ref'][10:] for row in rows
                    if isinstance(row, dict) and isinstance(row.get('ref'), str)
                    and row['ref'].startswith(prefix)
                    and row['ref'][len(prefix):].isdigit()}
            if not tags:
                raise ValueError('no stable releases found')
            return sorted(tags, key=lambda tag: tuple(map(int, tag.split('.'))))
        except (ValueError, KeyError, TypeError) as error:
            raise ProbeError(f'Invalid release catalog: {error}') from error

    def inspect(self, repository, reference, target_hash):
        revision = self.resolve(repository, reference)
        base = f'https://raw.githubusercontent.com/{repository}/{revision}'

        def read(relative):
            return self.read(f'{repository}/{revision}/{relative}', f'{base}/{relative}')

        recipe = read('tools/make_version.py')
        files = snapshot_files(recipe)
        with ThreadPoolExecutor(max_workers=4) as workers:
            data = list(workers.map(lambda f: read('runtime/vm/' + f), files))
        digest = hashlib.md5()
        for payload in data:
            digest.update(payload)
        source_hash = digest.hexdigest()
        return {'repository': repository, 'reference': reference, 'revision': revision,
                'source_hash': source_hash,
                'status': 'source_hash_match' if source_hash == target_hash else 'source_hash_mismatch',
                'recipe_sha256': hashlib.sha256(recipe).hexdigest(),
                'inputs': [{'path': 'runtime/vm/' + name, 'sha256': hashlib.sha256(payload).hexdigest()}
                           for name, payload in zip(files, data)]}


def probe(sources, candidates, target_hash):
    if not isinstance(target_hash, str) or not re.fullmatch(r'[0-9a-f]{32}', target_hash):
        raise ProbeError('Expected a 32-character lowercase snapshot hash')
    rows = []
    for repository, reference in dict.fromkeys(candidates):
        try:
            rows.append(sources.inspect(repository, reference, target_hash))
        except (ProbeError, requests.RequestException, OSError) as error:
            rows.append({'repository': repository, 'reference': reference,
                         'status': 'probe_error', 'reason': str(error)})
    matched = any(row['status'] == 'source_hash_match' for row in rows)
    failed = any(row['status'] == 'probe_error' for row in rows)
    status = 'SOURCE_IDENTITY_MATCH' if matched else 'INCONCLUSIVE' if failed else 'NO_SOURCE_IDENTITY_MATCH'
    groups = {}
    for row in rows:
        if 'source_hash' in row:
            groups.setdefault(row['source_hash'], []).append(
                {'repository': row['repository'], 'reference': row['reference'], 'revision': row['revision']})
    return {'snapshot_hash': target_hash, 'status': status, 'candidates': rows,
            'source_identity_groups': groups, 'limits': LIMITS}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, epilog=LIMITS)
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument('--libapp', type=Path, help='Read the hash from an ELF AOT library')
    target.add_argument('--snapshot-hash', help='Compare an already extracted format hash')
    parser.add_argument('--candidate', action='append', default=[], metavar='[OWNER/REPO@]REF',
                        help='Repeat for release tags or pinned source revisions; defaults to dart-lang/sdk')
    parser.add_argument('--series', action='append', default=[], metavar='MAJOR.MINOR',
                        help='Discover stable upstream release tags in this series; may be repeated')
    parser.add_argument('--cache-dir', type=Path, required=True, help='Separate source-only cache directory')
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--offline', action='store_true', help='Use cached sources only')
    mode.add_argument('--refresh', action='store_true', help='Refresh release/tag metadata; reuse pinned source files')
    parser.add_argument('--output', type=Path, help='Save the JSON report outside the code checkout')
    args = parser.parse_args(argv)
    try:
        if not args.candidate and not args.series:
            raise ProbeError('Choose at least one --candidate or --series')
        if args.cache_dir.resolve().is_relative_to(ROOT):
            raise ProbeError('Keep the source cache outside the code checkout')
        if args.output and (args.output.resolve().is_relative_to(ROOT) or
                            args.libapp and args.output.resolve() == args.libapp.resolve()):
            raise ProbeError('Keep the report outside the code checkout and input library')
        target_hash = args.snapshot_hash
        if args.libapp:
            sys.path.insert(0, str(ROOT))
            from elftools.common.exceptions import ELFError
            from extract_dart_info import extract_snapshot_hash_flags
            try:
                with contextlib.redirect_stdout(sys.stderr):
                    target_hash, _ = extract_snapshot_hash_flags(args.libapp)
            except ELFError as error:
                raise ProbeError(f'Invalid ELF input: {error}') from error
        candidates = []
        for candidate in args.candidate:
            repository, reference = candidate.rsplit('@', 1) if '@' in candidate else ('dart-lang/sdk', candidate)
            if not REPOSITORY.fullmatch(repository) or not REFERENCE.fullmatch(reference):
                raise ProbeError('Invalid source candidate; use [owner/repository@]release-or-commit')
            candidates.append((repository, reference))
        sources = Sources(args.cache_dir, args.offline, args.refresh)
        for series in args.series:
            candidates.extend(('dart-lang/sdk', tag) for tag in sources.releases(series))
        if len(set(candidates)) > 32:
            raise ProbeError('More than 32 candidates; split the probe into smaller batches')
        report = probe(sources, candidates, target_hash)
        serialized = json.dumps(report, indent=2) + '\n'
        if args.output:
            args.output.write_text(serialized)
        print(serialized, end='')
        return {'SOURCE_IDENTITY_MATCH': 0, 'NO_SOURCE_IDENTITY_MATCH': 1, 'INCONCLUSIVE': 2}[report['status']]
    except (ProbeError, OSError, RuntimeError, ValueError) as error:
        print(f'Source probe failed: {error}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
