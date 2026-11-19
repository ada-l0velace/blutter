"""Synthetic selection, pinned-source evidence and failure preservation."""
import hashlib
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
import reader_compatibility as compatibility
import reader_profiles as profiles
import blutter
import dartvm_fetch_build as build
from dartvm_fetch_build import DartLibInfo


class ReaderCompatibility(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.cache = Path(self.temporary.name)
        self.profile = profiles.RuntimeProfile('3.12.2', '1' * 32, '2' * 40,
                                               '3' * 40, 'AUTHORED_RUNTIME', 'authored.patch')
        self.registry = patch.dict(profiles.RUNTIME_PROFILES, {'authored': self.profile}, clear=True)
        self.registry.start()
        self.addCleanup(self.registry.stop)
        self.flags = {'product', 'no-shared_data', 'compressed-pointers'}
        no_download = patch.object(build, 'fetch_and_build', side_effect=AssertionError('Synthetic controls cannot download SDKs'))
        no_download.start()
        self.addCleanup(no_download.stop)

    def select(self, version='3.12.1', engine=None, **changes):
        arguments = dict(version=version, os_name='android', arch='arm64', compressed=True,
                         snapshot_hash=self.profile.snapshot_hash,
                         engine_ids=[engine or '4' * 40], flags=self.flags, cache=self.cache)
        arguments.update(changes)
        return compatibility.select_reader(**arguments)

    def test_registered_build_has_no_network_or_probe_requirement(self):
        with patch.object(compatibility, '_source') as source:
            selected = self.select('3.12.2', self.profile.engine)
        self.assertFalse(selected.needs_probe)
        self.assertEqual(selected.observed_version, '3.12.2')
        source.assert_not_called()

    def test_registered_relocation_profile_still_requires_a_probe(self):
        from dataclasses import replace
        with patch.dict(profiles.RUNTIME_PROFILES,
                        {'authored': replace(self.profile, abi_probe='guarded_relocations_v1')}, clear=True), \
                patch.object(compatibility, '_source') as source:
            selected = self.select('3.12.2', self.profile.engine)
            self.assertTrue(selected.needs_probe)
            source.assert_not_called()

    def test_candidate_preserves_observed_and_actual_reader_versions(self):
        with patch.object(compatibility, '_engine_source', return_value=('4' * 40, '5' * 40)), \
                patch.object(compatibility, '_contract', return_value=[{'path': 'authored', 'sha256': '6' * 64}]):
            selected = self.select()
        self.assertTrue(selected.needs_probe)
        self.assertEqual(selected.observed_version, '3.12.1')
        self.assertEqual(selected.source_evidence['reader_base'], self.profile.source_base)
        self.assertEqual(selected.source_evidence['observed_upstream_base'], '5' * 40)
        info = DartLibInfo(self.profile.version, 'android', 'arm64', True, self.profile.snapshot_hash)
        self.assertTrue(info.sdk_key.startswith('3.12.2_'))

    def test_unknown_engine_with_same_version_also_requires_qualification(self):
        with patch.object(compatibility, '_engine_source', return_value=('4' * 40, '5' * 40)), \
                patch.object(compatibility, '_contract', return_value=[]):
            self.assertTrue(self.select('3.12.2').needs_probe)

    def test_ineligible_targets_versions_hashes_and_flags_never_fetch_sources(self):
        for changes in [{'arch': 'x64'}, {'os_name': 'ios'}, {'compressed': False},
                        {'version': '3.11.1'}, {'snapshot_hash': '0' * 32}, {'flags': set()}]:
            with self.subTest(changes=changes), patch.object(compatibility, '_source') as source:
                with self.assertRaises(RuntimeError):
                    self.select(**changes)
                source.assert_not_called()

    def test_explicit_unsupported_format_cannot_enter_candidates(self):
        with patch.dict(profiles.UNSUPPORTED_FORMATS, {self.profile.snapshot_hash: 'authored refusal'}), \
                patch.object(compatibility, '_source') as source:
            with self.assertRaisesRegex(RuntimeError, 'Unsupported snapshot format'):
                self.select()
            source.assert_not_called()

    def test_different_source_contract_remains_an_error(self):
        with patch.object(compatibility, '_engine_source', return_value=('4' * 40, '5' * 40)), \
                patch.object(compatibility, '_contract', side_effect=RuntimeError('authored layout mismatch')):
            with self.assertRaisesRegex(RuntimeError, 'No reader candidate passed.*layout mismatch'):
                self.select()

    def test_source_comparison_checks_every_contract_file(self):
        with patch.object(compatibility, '_source', return_value=b'authored source') as source:
            result = compatibility._contract(self.cache, '3' * 40, '5' * 40)
        self.assertEqual(len(result), len(compatibility.CONTRACT_FILES))
        self.assertEqual(source.call_count, len(compatibility.CONTRACT_FILES) * 2)
        self.assertTrue(all(r['sha256'] == hashlib.sha256(b'authored source').hexdigest() for r in result))

    def test_one_changed_abi_file_rejects_candidate(self):
        def source(cache, repository, revision, path):
            return b'changed' if revision == '5' * 40 and path.endswith('/thread.h') else b'authored'
        with patch.object(compatibility, '_source', side_effect=source):
            with self.assertRaisesRegex(RuntimeError, 'thread.h'):
                compatibility._contract(self.cache, '3' * 40, '5' * 40)

    def test_engine_identity_must_match_version_and_be_unique(self):
        def source(cache, repository, revision, path):
            if path == 'DEPS':
                return b"'dart_revision': '" + b'5' * 40 + b"'"
            return b'CHANNEL stable\nMAJOR 3\nMINOR 12\nPATCH 1\n'
        with patch.object(compatibility, '_source', side_effect=source):
            self.assertEqual(compatibility._engine_source(self.cache, ['4' * 40], '3.12.1'), ('4' * 40, '5' * 40))
            for engines, version in [(['4' * 40], '3.12.2'), (['4' * 40, '6' * 40], '3.12.1')]:
                with self.assertRaisesRegex(RuntimeError, 'one public engine'):
                    compatibility._engine_source(self.cache, engines, version)

    def test_cached_engine_mapping_still_reads_pinned_dependency_and_version(self):
        def source(cache, repository, revision, path):
            if path == 'DEPS':
                if revision == '6' * 40:
                    response = requests.Response(); response.status_code = 404
                    raise requests.HTTPError(response=response)
                return b"'dart_revision': '" + b'5' * 40 + b"'"
            return b'CHANNEL stable\nMAJOR 3\nMINOR 12\nPATCH 1\n'
        with patch.object(compatibility, '_source', side_effect=source) as fetch:
            expected = compatibility._engine_source(self.cache, ['4' * 40, '6' * 40], '3.12.1')
            fetch.reset_mock()
            self.assertEqual(compatibility._engine_source(self.cache, ['4' * 40, '6' * 40], '3.12.1'), expected)
            self.assertEqual(fetch.call_count, 2)
            self.assertTrue(all(c.args[2] != '6' * 40 for c in fetch.call_args_list))

    def request(self, candidate=True):
        info = DartLibInfo(self.profile.version, 'android', 'arm64', True, self.profile.snapshot_hash)
        info.reader_selection = compatibility.ReaderSelection('authored', '3.12.1', '4' * 40,
                                                               {} if candidate else None)
        info.libflutter_path = 'authored-engine'
        return blutter.BlutterInput('authored-app', info, str(self.cache / 'output'), False, False, False)

    def test_analysis_failure_after_a_successful_probe_is_propagated(self):
        import subprocess
        metadata = {'reader_probe_schema': 1}
        proof = {'payload_count': 2, 'vm_stub_count': 2, 'guard_sites_checked': 2}
        error = subprocess.CalledProcessError(2, ['authored-analysis'])
        with patch.object(blutter, 'read_verified', return_value=metadata), \
                patch.object(build, 'refresh_call_input_capability', side_effect=lambda i, p, m: m), \
                patch('reader_probe.run_probe', return_value=proof) as native, \
                patch.object(compatibility, 'write_selection_report'), \
                patch.object(blutter, 'cmake_blutter') as compile_call, \
                patch.object(blutter, 'run_blutter', side_effect=error) as export:
            with self.assertRaises(subprocess.CalledProcessError) as raised:
                blutter.build_and_run(self.request())
            self.assertIs(raised.exception, error)
            native.assert_called_once()
            export.assert_called_once()
            compile_call.assert_not_called()

    def test_probe_failure_prevents_export_and_success_report(self):
        with patch.object(blutter, 'read_verified', return_value={'reader_probe_schema': 1}), \
                patch.object(build, 'refresh_call_input_capability', side_effect=lambda i, p, m: m), \
                patch('reader_probe.run_probe', side_effect=RuntimeError('authored probe refusal')), \
                patch.object(compatibility, 'write_selection_report') as report, \
                patch.object(blutter, 'run_blutter') as export:
            with self.assertRaisesRegex(RuntimeError, 'authored probe refusal'):
                blutter.build_and_run(self.request())
            report.assert_not_called()
            export.assert_not_called()

    def test_registered_stub_abi_runs_its_probe_and_reaches_export(self):
        from dataclasses import replace
        from contextlib import redirect_stdout
        from io import StringIO
        profile = replace(self.profile, abi_probe='arm64_stub_layout_v1')
        proof = {'abi_kind': profile.abi_probe, 'payload_count': 2,
                 'vm_stub_count': 3, 'abi_stubs_checked': 2, 'thread_accesses_checked': 5}
        output = StringIO()
        with patch.dict(profiles.RUNTIME_PROFILES, {'authored': profile}), \
                patch.object(blutter, 'read_verified', return_value={'reader_probe_schema': 1}), \
                patch.object(build, 'refresh_call_input_capability', side_effect=lambda i, p, m: m), \
                patch('reader_probe.run_probe', return_value=proof) as native, \
                patch.object(compatibility, 'write_selection_report') as report, \
                patch.object(blutter, 'run_blutter') as export, redirect_stdout(output):
            request = self.request(candidate=False)
            blutter.build_and_run(request)
            native.assert_called_once_with(request.blutter_file, request.libapp_path,
                                           request.dart_info.libflutter_path,
                                           expected_abi=profile.abi_probe)
            report.assert_called_once()
            export.assert_called_once()
        self.assertIn('2 ABI stubs, 5 Thread accesses', output.getvalue())
        self.assertIn('Registered engine; per-input proof required', output.getvalue())

    def test_unknown_registered_proof_kind_cannot_skip_validation(self):
        from dataclasses import replace
        from reader_probe import validate_probe
        kind = 'authored-unsupported'
        with patch.dict(profiles.RUNTIME_PROFILES, {'authored': replace(self.profile, abi_probe=kind)}):
            self.assertTrue(self.request(candidate=False).dart_info.reader_selection.needs_probe)
            with self.assertRaisesRegex(RuntimeError, 'unsupported reader ABI proof kind'):
                validate_probe({'schema': 1, 'status': 'deserialized', 'abi_kind': kind},
                               'unused-app', 'unused-engine', expected_abi=kind)

    def test_older_cached_candidate_requires_a_probe_capable_rebuild(self):
        with patch.object(blutter, 'read_verified', return_value={'schema': 1}), \
                patch.object(build, 'refresh_call_input_capability', side_effect=lambda i, p, m: m), \
                patch.object(blutter, 'cmake_blutter', side_effect=RuntimeError('authored rebuild')) as compile_call, \
                patch('reader_probe.run_probe') as native, patch.object(blutter, 'run_blutter') as export:
            with self.assertRaisesRegex(RuntimeError, 'authored rebuild'):
                blutter.build_and_run(self.request())
            compile_call.assert_called_once()
            native.assert_not_called()
            export.assert_not_called()

    def test_registered_build_does_not_require_a_probe_capable_rebuild(self):
        with patch.object(blutter, 'read_verified', return_value={'schema': 1}), \
                patch.object(build, 'refresh_call_input_capability', side_effect=lambda i, p, m: m), \
                patch.object(blutter, 'cmake_blutter') as compile_call, \
                patch('reader_probe.run_probe') as native, patch.object(blutter, 'run_blutter') as export:
            blutter.build_and_run(self.request(candidate=False))
            compile_call.assert_not_called()
            native.assert_not_called()
            export.assert_called_once()

    def test_source_cache_uses_pinned_revision_and_limits_downloads(self):
        response = MagicMock()
        response.__enter__.return_value = response
        response.iter_content.return_value = [b'authored']
        with patch.object(compatibility.requests, 'get', return_value=response) as get:
            for _ in range(2):
                self.assertEqual(compatibility._source(self.cache, 'dart-lang/sdk', '3' * 40, 'tools/VERSION'), b'authored')
        get.assert_called_once()
        with patch.object(compatibility, 'MAX_SOURCE_BYTES', 4), \
                patch.object(compatibility.requests, 'get', return_value=response):
            with self.assertRaisesRegex(RuntimeError, 'size limit'):
                compatibility._source(self.cache, 'dart-lang/sdk', '7' * 40, 'tools/VERSION')
        self.assertFalse((self.cache / 'sources/dart-lang/sdk' / ('7' * 40) / 'tools/VERSION').exists())

    def test_macro_emission_is_unique_for_shared_reader_implementations(self):
        with patch.dict(profiles.RUNTIME_PROFILES, {'authored_alias': self.profile}):
            self.assertEqual(profiles.profile_cmake_options('authored'), ['-DAUTHORED_RUNTIME=ON'])
            self.assertEqual(profiles.profile_cmake_options(None), ['-DAUTHORED_RUNTIME=OFF'])
            self.assertEqual(profiles.candidate_profiles('3.12.1', 'android', 'arm64', True, '1' * 32), ('authored',))

    def test_exact_lookup_checks_all_registered_versions_of_a_format(self):
        other = profiles.RuntimeProfile('3.12.1', self.profile.snapshot_hash, '4' * 40,
                                         '5' * 40, self.profile.macro, self.profile.patch)
        with patch.dict(profiles.RUNTIME_PROFILES, {'authored_earlier': other}):
            self.assertEqual(profiles.reader_profile('3.12.1', 'android', 'arm64', True, '1' * 32),
                             'authored_earlier')
            self.assertEqual(profiles.reader_profile('3.12.2', 'android', 'arm64', True, '1' * 32),
                             'authored')
            self.assertEqual(profiles.profile_cmake_options('authored_earlier'), ['-DAUTHORED_RUNTIME=ON'])
            self.assertEqual(profiles.candidate_profiles('3.12.0', 'android', 'arm64', True, '1' * 32),
                             ('authored', 'authored_earlier'))


if __name__ == '__main__':
    unittest.main()
