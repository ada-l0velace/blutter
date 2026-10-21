#!/usr/bin/env python3
"""Check reader identity and cache isolation without downloading an SDK."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from dartvm_fetch_build import DartLibInfo
from extract_dart_info import find_snapshot_symbol
from reader_profiles import (
    SHOREBIRD_ENGINE, SHOREBIRD_HASH, SHOREBIRD_PROFILE,
    reader_profile, verify_engine_profile,
)


class ReaderProfiles(unittest.TestCase):
    def test_known_reader(self):
        self.assertEqual(reader_profile('3.13.5', 'android', 'arm64', True,
                                        SHOREBIRD_HASH), SHOREBIRD_PROFILE)

    def test_ordinary_readers_keep_existing_keys(self):
        for version in ('3.11.0', '3.12.0', '3.13.0', '3.13.5'):
            with self.subTest(version=version):
                info = DartLibInfo(version, 'android', 'arm64', True, '0' * 32)
                self.assertIsNone(info.reader_profile)
                self.assertEqual(info.sdk_key, version)
                self.assertEqual(info.lib_name, f'dartvm{version}_android_arm64')

    def test_known_hash_with_wrong_target_is_rejected(self):
        for target in [('3.13.0', 'android', 'arm64', True),
                       ('3.13.5', 'ios', 'arm64', True),
                       ('3.13.5', 'android', 'x64', True),
                       ('3.13.5', 'android', 'arm64', False)]:
            with self.subTest(target=target), self.assertRaises(RuntimeError):
                reader_profile(*target, SHOREBIRD_HASH)

    def test_engine_and_flags_are_required(self):
        flags = {'product', 'no-shared_data', 'compressed-pointers'}
        verify_engine_profile(SHOREBIRD_PROFILE, [SHOREBIRD_ENGINE], flags)
        with self.assertRaises(RuntimeError):
            verify_engine_profile(SHOREBIRD_PROFILE, ['0' * 40], flags)
        for flag in flags:
            with self.subTest(missing=flag), self.assertRaises(RuntimeError):
                verify_engine_profile(SHOREBIRD_PROFILE, [SHOREBIRD_ENGINE], flags - {flag})

    def test_custom_and_official_cache_keys_cannot_collide(self):
        custom = DartLibInfo('3.13.5', 'android', 'arm64', True, SHOREBIRD_HASH)
        official = DartLibInfo('3.13.5', 'android', 'arm64', True, '0' * 32)
        self.assertNotEqual(custom.sdk_key, official.sdk_key)
        self.assertNotEqual(custom.lib_name, official.lib_name)
        self.assertIn(SHOREBIRD_HASH, custom.sdk_key)

    def test_both_snapshot_data_names(self):
        class Symbols:
            def __init__(self, name): self.name = name
            def get_symbol_by_name(self, name):
                return [self.name] if name == self.name else None

        for name in ('_kDartVmSnapshotData', '_kDartSnapshotData'):
            self.assertEqual(find_snapshot_symbol(Symbols(name)), name)
        self.assertIsNone(find_snapshot_symbol(Symbols('_kDartSnapshotText')))
        self.assertIsNone(find_snapshot_symbol(None))


if __name__ == '__main__':
    unittest.main()
