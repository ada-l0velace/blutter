"""Source-discovery controls using authored recipes and source bytes only."""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('runtime_probe', ROOT / 'scripts/probe_runtime_sources.py')
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)

RECIPE = b'''VM_SNAPSHOT_FILES = ['layout.h', 'snapshot.cc']
def MakeSnapshotHashString():
    value = hashlib.md5()
    for name in VM_SNAPSHOT_FILES:
        location = os.path.join(utils.DART_DIR, 'runtime', 'vm', name)
        with open(location, 'rb') as source:
            value.update(source.read())
    return value.hexdigest()
'''
PAYLOADS = [b'authored layout\n', b'authored snapshot implementation\n']
TARGET = hashlib.md5(b''.join(PAYLOADS)).hexdigest()
COMMIT = '1' * 40


def populate(root, reference='3.10.0', recipe=RECIPE, payloads=PAYLOADS):
    base = root / 'dart-lang/sdk'
    tag = base / 'resolutions' / (reference + '.json')
    tag.parent.mkdir(parents=True, exist_ok=True)
    tag.write_text(json.dumps({'sha': COMMIT}))
    files = {'tools/make_version.py': recipe,
             'runtime/vm/layout.h': payloads[0], 'runtime/vm/snapshot.cc': payloads[1]}
    for name, data in files.items():
        path = base / COMMIT / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)


class RuntimeSources(unittest.TestCase):
    def test_release_labels_do_not_override_source_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for version in ('3.10.0', '3.11.0', '3.12.0'):
                populate(root, version)
            report = probe.probe(probe.Sources(root, offline=True),
                                 [('dart-lang/sdk', v) for v in ('3.10.0', '3.11.0', '3.12.0')], TARGET)
            self.assertEqual(report['status'], 'SOURCE_IDENTITY_MATCH')
            self.assertEqual(len(report['candidates']), 3)
            self.assertTrue(all(r['revision'] == COMMIT for r in report['candidates']))
            self.assertIn('not proof', report['limits'])

    def test_different_bytes_and_input_order_do_not_match(self):
        for recipe, payloads in [
                (RECIPE, [b'another layout\n', PAYLOADS[1]]),
                (RECIPE.replace(b"['layout.h', 'snapshot.cc']", b"['snapshot.cc', 'layout.h']"), PAYLOADS)]:
            with self.subTest(recipe=recipe), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                populate(root, recipe=recipe, payloads=payloads)
                report = probe.probe(probe.Sources(root, offline=True), [('dart-lang/sdk', '3.10.0')], TARGET)
                self.assertEqual(report['status'], 'NO_SOURCE_IDENTITY_MATCH')

    def test_missing_cache_and_changed_recipe_are_inconclusive(self):
        for recipe in (None, RECIPE.replace(b'hashlib.md5()', b'hashlib.sha256()')):
            with self.subTest(recipe=recipe), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                if recipe:
                    populate(root, recipe=recipe)
                with patch.object(probe.Sources, 'download', side_effect=AssertionError('unexpected network')):
                    report = probe.probe(probe.Sources(root, offline=True), [('dart-lang/sdk', '3.10.0')], TARGET)
                self.assertEqual(report['status'], 'INCONCLUSIVE')
                self.assertEqual(report['candidates'][0]['status'], 'probe_error')

    def test_source_recipe_is_not_executed(self):
        recipe = RECIPE + b"\nraise RuntimeError('must never execute downloaded code')\n"
        self.assertEqual(probe.snapshot_files(recipe), ['layout.h', 'snapshot.cc'])

    def test_dynamic_duplicate_and_unsafe_lists_are_rejected(self):
        for replacement in [b"['../layout.h']", b"['layout.h', 'layout.h']", b'build_list()', b'[]']:
            with self.subTest(replacement=replacement), self.assertRaises(probe.ProbeError):
                probe.snapshot_files(RECIPE.replace(b"['layout.h', 'snapshot.cc']", replacement))

    def test_unrecognized_recipe_steps_are_rejected(self):
        for recipe in [RECIPE.replace(b'value.update(source.read())', b'value.update(source.read()[::-1])'),
                       RECIPE.replace(b'return value.hexdigest()', b'return "0" * 32'),
                       RECIPE.replace(b"'rb'", b"'r'"),
                       RECIPE.replace(b'def MakeSnapshotHashString():', b'def MakeSnapshotHashString(extra):')]:
            with self.subTest(recipe=recipe), self.assertRaises(probe.ProbeError):
                probe.snapshot_files(recipe)

    def test_stable_release_discovery_is_scoped_and_sorted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            catalog = root / 'dart-lang/sdk/releases/3.10.json'
            catalog.parent.mkdir(parents=True)
            catalog.write_text(json.dumps([{'ref': 'refs/tags/' + version} for version in
                                          ('3.10.9', '3.10.2', '3.10.0-1.0.dev', '3.100.1', '3.10.2')]))
            self.assertEqual(probe.Sources(root, offline=True).releases('3.10'), ['3.10.2', '3.10.9'])

    def test_pinned_downloads_and_cache_reuse(self):
        downloads = []

        def fetch(url):
            downloads.append(url)
            if '/commits/' in url:
                return json.dumps({'sha': COMMIT}).encode()
            self.assertIn('/' + COMMIT + '/', url)
            if url.endswith('/make_version.py'):
                return RECIPE
            return PAYLOADS[0] if url.endswith('/layout.h') else PAYLOADS[1]

        with tempfile.TemporaryDirectory() as directory:
            with patch.object(probe.Sources, 'download', side_effect=fetch):
                sources = probe.Sources(directory)
                first = sources.inspect('dart-lang/sdk', '3.10.0', TARGET)
            self.assertEqual(len(downloads), 4)
            with patch.object(probe.Sources, 'download', side_effect=AssertionError('network on cached read')):
                second = probe.Sources(directory, offline=True).inspect('dart-lang/sdk', '3.10.0', TARGET)
            self.assertEqual(first, second)
            self.assertEqual(first['status'], 'source_hash_match')

    def test_refresh_updates_metadata_but_reuses_immutable_sources(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            populate(root)
            with patch.object(probe.Sources, 'download', return_value=json.dumps({'sha': COMMIT}).encode()) as fetch:
                result = probe.Sources(root, refresh=True).inspect('dart-lang/sdk', '3.10.0', TARGET)
            self.assertEqual(result['status'], 'source_hash_match')
            self.assertEqual(fetch.call_count, 1)
            self.assertTrue(fetch.call_args.args[0].endswith('/commits/3.10.0'))
        with self.assertRaises(probe.ProbeError):
            probe.Sources('.', offline=True, refresh=True)

    def test_invalid_reference_and_cache_escape_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            sources = probe.Sources(directory, offline=True)
            for repository, reference in [('dart-lang/sdk', '../main'), ('../sdk', '3.10.0')]:
                with self.subTest(reference=reference), self.assertRaises(probe.ProbeError):
                    sources.resolve(repository, reference)
            with self.assertRaises(probe.ProbeError):
                sources.location('../escape')

    def test_cli_reports_match_mismatch_and_missing_source(self):
        for value, expected in [(TARGET, 0), ('0' * 32, 1)]:
            with self.subTest(value=value), tempfile.TemporaryDirectory() as directory:
                populate(Path(directory))
                command = [sys.executable, str(ROOT / 'scripts/probe_runtime_sources.py'),
                           '--snapshot-hash', value, '--candidate', '3.10.0',
                           '--cache-dir', directory, '--offline']
                result = subprocess.run(command, capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, expected, result.stderr)
                self.assertEqual(len(json.loads(result.stdout)['candidates']), 1)
        with tempfile.TemporaryDirectory() as directory:
            report = probe.probe(probe.Sources(directory, offline=True), [('dart-lang/sdk', '3.11.0')], TARGET)
            self.assertEqual(report['status'], 'INCONCLUSIVE')

    def test_cli_refuses_invalid_input_and_input_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            library = root / 'authored-invalid.so'
            library.write_bytes(b'authored invalid ELF input')
            command = [sys.executable, str(ROOT / 'scripts/probe_runtime_sources.py'),
                       '--libapp', str(library), '--candidate', '3.10.0',
                       '--cache-dir', str(root / 'cache'), '--offline']
            invalid = subprocess.run(command, capture_output=True, text=True, timeout=10)
            self.assertEqual(invalid.returncode, 2)
            self.assertIn('Invalid ELF input', invalid.stderr)
            overwrite = subprocess.run(command + ['--output', str(library)],
                                       capture_output=True, text=True, timeout=10)
            self.assertEqual(overwrite.returncode, 2)
            self.assertIn('input library', overwrite.stderr)
            self.assertEqual(library.read_bytes(), b'authored invalid ELF input')


if __name__ == '__main__':
    unittest.main()
