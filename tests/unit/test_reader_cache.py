"""Reader selection and artifact reuse against authored source/artifact data."""
from pathlib import Path
import json
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
import blutter
import dartvm_fetch_build as build
from reader_cache import read_verified, write_verified, metadata_path
from reader_profiles import UNSUPPORTED_FORMATS, SHOREBIRD_HASH, SHOREBIRD_BASE
from reader_profiles import RUNTIME_PROFILES


class ReaderCache(unittest.TestCase):
    def test_profile_cache_cannot_cross_source_bases_or_runtime_formats(self):
        for name, profile in RUNTIME_PROFILES.items():
            with self.subTest(profile=name), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / 'lib/authored-runtime'
                path.parent.mkdir()
                path.write_bytes(b'authored library')
                info = build.DartLibInfo(profile.version, 'android', 'arm64', True, profile.snapshot_hash)
                self.headers(path, info)
                source = {'source_revision': profile.source_base, 'source_hash': '0' * 32}
                write_verified(path, info, 'runtime', source)
                self.assertIsNotNone(read_verified(path, info, 'runtime'))
                for other in RUNTIME_PROFILES.values():
                    if other != profile:
                        other_info = build.DartLibInfo(other.version, 'android', 'arm64', True, other.snapshot_hash)
                        self.assertIsNone(read_verified(path, other_info, 'runtime'))
                metadata = json.loads(metadata_path(path).read_text())
                metadata['source_revision'] = '2' * 40
                metadata_path(path).write_text(json.dumps(metadata))
                self.assertIsNone(read_verified(path, info, 'runtime'))

    def info(self, snapshot='0' * 32, compressed=True):
        return build.DartLibInfo('3.11.0', 'android', 'arm64', compressed, snapshot)

    def source(self, snapshot='0' * 32):
        return {'source_revision': '1' * 40, 'source_hash': snapshot}

    def headers(self, library, info):
        root = library.parent.parent / 'include' / ('dartvm' + info.sdk_key)
        root.mkdir(parents=True, exist_ok=True)
        header = root / 'authored.h'
        header.write_text('struct AuthoredLayout {};\n')
        return header

    def test_missing_corrupt_and_changed_artifacts_are_not_reused(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'authored-reader'
            path.write_bytes(b'authored binary')
            info = self.info()
            self.assertIsNone(read_verified(path, info, 'reader'))
            metadata_path(path).write_text('{invalid')
            self.assertIsNone(read_verified(path, info, 'reader'))
            write_verified(path, info, 'reader', self.source())
            self.assertIsNotNone(read_verified(path, info, 'reader'))
            path.write_bytes(b'another authored binary')
            self.assertIsNone(read_verified(path, info, 'reader'))

    def test_format_mode_kind_and_profile_are_separate_identities(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'authored-reader'
            path.write_bytes(b'authored binary')
            info = self.info()
            write_verified(path, info, 'reader', self.source())
            self.assertIsNone(read_verified(path, self.info('2' * 32), 'reader'))
            self.assertIsNone(read_verified(path, self.info(compressed=False), 'reader'))
            self.assertIsNone(read_verified(path, info, 'runtime'))
            self.assertIsNone(read_verified(path, info, 'reader', no_analysis=True))
            info.reader_profile = 'authored-other-profile'
            self.assertIsNone(read_verified(path, info, 'reader'))

    def test_official_source_mismatch_invalidates_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'lib/authored-runtime'
            path.parent.mkdir()
            path.write_bytes(b'authored static library')
            info = self.info()
            self.headers(path, info)
            write_verified(path, info, 'runtime', self.source())
            data = json.loads(metadata_path(path).read_text())
            data['source_hash'] = '3' * 32
            metadata_path(path).write_text(json.dumps(data))
            self.assertIsNone(read_verified(path, info, 'runtime'))

    def test_custom_cache_tracks_the_bundled_patch_and_source_base(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'lib/authored-custom-runtime'
            path.parent.mkdir()
            path.write_bytes(b'authored static library')
            info = build.DartLibInfo('3.13.5', 'android', 'arm64', True, SHOREBIRD_HASH)
            self.headers(path, info)
            source = {'source_revision': SHOREBIRD_BASE, 'source_hash': '0' * 32}
            with patch('reader_cache.profile_patch_hash', return_value='1' * 64):
                write_verified(path, info, 'runtime', source)
                self.assertIsNotNone(read_verified(path, info, 'runtime'))
            with patch('reader_cache.profile_patch_hash', return_value='2' * 64):
                self.assertIsNone(read_verified(path, info, 'runtime'))
            data = json.loads(metadata_path(path).read_text())
            data['source_revision'] = '3' * 40
            metadata_path(path).write_text(json.dumps(data))
            with patch('reader_cache.profile_patch_hash', return_value='1' * 64):
                self.assertIsNone(read_verified(path, info, 'runtime'))

    def test_runtime_cache_requires_unchanged_installed_headers(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'lib/authored-runtime'
            path.parent.mkdir()
            path.write_bytes(b'authored static library')
            info = self.info()
            header = self.headers(path, info)
            write_verified(path, info, 'runtime', self.source())
            header.write_text('struct DifferentLayout {};\n')
            self.assertIsNone(read_verified(path, info, 'runtime'))
            header.unlink()
            self.assertIsNone(read_verified(path, info, 'runtime'))

    def test_artifacts_from_another_host_are_not_reused(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'authored-reader'
            path.write_bytes(b'authored binary')
            info = self.info()
            write_verified(path, info, 'reader', self.source())
            with patch('reader_cache.platform.machine', return_value='authored-other-host'):
                self.assertIsNone(read_verified(path, info, 'reader'))

    def test_unsupported_runtime_is_rejected_before_build_or_download(self):
        with patch.dict(UNSUPPORTED_FORMATS, {'1' * 32: 'authored unsupported format'}, clear=True):
            with patch.object(build.subprocess, 'run') as run:
                with self.assertRaisesRegex(RuntimeError, 'Unsupported snapshot format'):
                    build.DartLibInfo('3.12.2', 'android', 'arm64', True, '1' * 32)
                run.assert_not_called()

    def test_unmatched_source_never_reaches_build_or_hash_generation(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(build.subprocess, 'check_output', side_effect=[directory, '1' * 40]), \
                patch.object(build, 'source_snapshot_hash', return_value='3' * 32), \
                patch.object(build.subprocess, 'run') as run:
            with self.assertRaisesRegex(RuntimeError, 'reader hash will not be replaced'):
                build.cmake_dart(self.info(), directory)
            run.assert_not_called()

    def test_parent_git_repository_is_not_sdk_provenance(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'authored-sdk'
            source.mkdir()
            with patch.object(build.subprocess, 'check_output', return_value=str(root)), \
                    patch.object(build, 'source_snapshot_hash') as compute:
                with self.assertRaisesRegex(build.ReaderSourceMismatch, 'parent repository'):
                    build.verify_dart_sources(self.info(), source)
                compute.assert_not_called()

    def test_noncompressed_packages_have_distinct_names(self):
        self.assertNotEqual(self.info().sdk_key, self.info(compressed=False).sdk_key)

    def test_outdated_custom_sources_are_preserved_before_replacement(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            info = build.DartLibInfo('3.13.5', 'android', 'arm64', True, SHOREBIRD_HASH)
            old = root / ('v' + info.sdk_key)
            old.mkdir()
            (old / 'authored-change').write_text('preserve this source change')
            attempts = 0

            def checkout(_):
                nonlocal attempts
                attempts += 1
                if attempts == 1:
                    raise build.ReaderSourceMismatch('authored outdated patch')
                old.mkdir()
                (old / 'authored-fresh').touch()
                return str(old)

            with patch.object(build, 'SDK_DIR', str(root)), \
                    patch.object(build, 'checkout_dart', side_effect=checkout), \
                    patch.object(build, 'cmake_dart') as compile_call:
                build.fetch_and_build(info)
            backups = list(root.glob('*.unverified-*'))
            self.assertEqual(len(backups), 1)
            self.assertEqual((backups[0] / 'authored-change').read_text(), 'preserve this source change')
            self.assertTrue((old / 'authored-fresh').exists())
            compile_call.assert_called_once_with(info, str(old))

    def test_invalid_identifiers_cannot_enter_source_or_cache_paths(self):
        for version, target, arch, snapshot in [('../outside', 'android', 'arm64', '0' * 32),
                                              ('3.11.0', '../outside', 'arm64', '0' * 32),
                                              ('3.11.0', 'android', 'other', '0' * 32),
                                              ('3.11.0', 'android', 'arm64', '../outside')]:
            with self.subTest(version=version, target=target), self.assertRaises(ValueError):
                build.DartLibInfo(version, target, arch, True, snapshot)

    def test_unverified_binary_is_rebuilt_from_verified_runtime(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            info = self.info()
            request = blutter.BlutterInput('authored-input', info, str(root / 'out'), False, False, False)
            request.blutter_file = str(root / 'authored-reader')
            Path(request.blutter_file).write_bytes(b'old unverified artifact')
            package = root / 'packages/lib'
            package.mkdir(parents=True)
            library = package / ('lib' + info.lib_name + '.a')
            library.write_bytes(b'authored runtime')
            self.headers(library, info)
            write_verified(library, info, 'runtime', self.source())

            def compile_reader(item):
                Path(item.blutter_file).write_bytes(b'new authored artifact')

            with patch.object(blutter, 'PKG_LIB_DIR', str(package)), \
                    patch.object(blutter, 'cmake_blutter', side_effect=compile_reader) as compile_call, \
                    patch.object(build, 'fetch_and_build') as fetch, patch.object(blutter.subprocess, 'run'):
                blutter.build_and_run(request)
            compile_call.assert_called_once()
            fetch.assert_not_called()
            self.assertIsNotNone(read_verified(request.blutter_file, info, 'reader'))


if __name__ == '__main__':
    unittest.main()
