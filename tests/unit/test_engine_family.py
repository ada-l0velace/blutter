"""Engine-family selection uses authored exports, not compiler comments."""
from pathlib import Path
import sys
import unittest
from unittest.mock import patch, mock_open

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
import blutter
import extract_dart_info as extract
from reader_profiles import RUNTIME_PROFILES


class Symbols:
    def __init__(self, names=(), kind='STT_FUNC', binding='STB_GLOBAL', section=1):
        self.names = set(names)
        self.symbol = {'st_shndx': section, 'st_info': {'type': kind, 'bind': binding}}

    def num_symbols(self):
        return len(self.names)

    def get_symbol_by_name(self, name):
        return [self.symbol] if name in self.names else None


class EngineFamily(unittest.TestCase):
    exports = ('shorebird_init', 'shorebird_current_boot_patch_number')

    def test_defined_export_pair_identifies_family(self):
        for binding in ('STB_GLOBAL', 'STB_WEAK'):
            self.assertTrue(extract.has_shorebird_exports(Symbols(self.exports, binding=binding)))

    def test_absent_partial_imported_and_nonfunction_markers_are_not_enough(self):
        self.assertFalse(extract.has_shorebird_exports(None))
        for symbols in (Symbols(), Symbols(self.exports[:1]), Symbols(self.exports[1:]),
                        Symbols(self.exports, section='SHN_UNDEF'), Symbols(self.exports, kind='STT_OBJECT'),
                        Symbols(self.exports, binding='STB_LOCAL'), Symbols(['shorebird_init_extra', 'rustc'])):
            with self.subTest(symbols=symbols.names):
                self.assertFalse(extract.has_shorebird_exports(symbols))

    def test_rust_comment_does_not_select_shorebird(self):
        class Engine:
            def get_section_by_name(self, name):
                if name == '.comment':
                    raise AssertionError('Compiler comments must not select the engine family')
                return Symbols(['authored_rust_function'])

        with patch('builtins.open', mock_open(read_data=b'rustc authored')), \
                patch.object(extract, 'ELFFile', return_value=Engine()):
            self.assertFalse(extract.is_shorebird_engine('authored-engine'))

    def test_excessive_symbol_table_is_rejected(self):
        symbols = Symbols(self.exports)
        symbols.num_symbols = lambda: (1 << 20) + 1
        with self.assertRaisesRegex(RuntimeError, 'detection limit'):
            extract.has_shorebird_exports(symbols)

    def test_unknown_shorebird_stops_before_build_and_network(self):
        metadata = ('3.0.0', '1' * 32, ['product', 'no-shared_data', 'compressed-pointers'], 'arm64', 'android')
        with patch.object(extract, 'is_shorebird_engine', return_value=True), \
                patch.object(extract, 'extract_dart_info', return_value=metadata) as identify, \
                patch.object(blutter, 'build_and_run') as build, \
                patch.object(extract.requests, 'head') as head, patch.object(extract.requests, 'get') as get:
            with self.assertRaisesRegex(RuntimeError, 'No upstream runtime will be downloaded'):
                blutter.main2('authored-input', 'authored-engine', 'authored-output', False, False, False)
            identify.assert_called_once_with('authored-input', 'authored-engine', allow_upstream_lookup=False)
            build.assert_not_called()
            head.assert_not_called()
            get.assert_not_called()

    def test_missing_shorebird_version_never_uses_upstream_lookup(self):
        with patch.object(extract, 'extract_snapshot_hash_flags', return_value=('1' * 32, [])), \
                patch.object(extract, 'extract_libflutter_info', return_value=(['2' * 40], None, 'arm64', 'android')), \
                patch.object(extract, 'get_dart_sdk_url_size') as lookup:
            with self.assertRaisesRegex(RuntimeError, 'upstream SDK lookup is disabled'):
                extract.extract_dart_info('authored-input', 'authored-engine', allow_upstream_lookup=False)
            lookup.assert_not_called()

    def test_known_readers_still_require_engine_verification(self):
        for profile in RUNTIME_PROFILES.values():
            metadata = (profile.version, profile.snapshot_hash, ['product', 'no-shared_data', 'compressed-pointers'], 'arm64', 'android')
            with patch.object(extract, 'is_shorebird_engine', return_value=True), \
                    patch.object(extract, 'extract_dart_info', return_value=metadata), \
                    patch.object(extract, 'extract_libflutter_info', return_value=([profile.engine], profile.version, 'arm64', 'android')):
                self.assertIsNotNone(blutter.get_dart_lib_info('authored-input', 'authored-engine').reader_profile)
            with patch.object(extract, 'is_shorebird_engine', return_value=True), \
                    patch.object(extract, 'extract_dart_info', return_value=metadata), \
                    patch.object(extract, 'extract_libflutter_info', return_value=(['2' * 40], profile.version, 'arm64', 'android')):
                with self.assertRaisesRegex(RuntimeError, 'engine revision is unverified'):
                    blutter.get_dart_lib_info('authored-input', 'authored-engine')

    def test_other_engines_keep_existing_source_verification_path(self):
        metadata = ('3.0.0', '1' * 32, ['compressed-pointers'], 'arm64', 'android')
        with patch.object(extract, 'is_shorebird_engine', return_value=False), \
                patch.object(extract, 'extract_dart_info', return_value=metadata) as identify:
            self.assertIsNone(blutter.get_dart_lib_info('authored-input', 'authored-engine').reader_profile)
            self.assertTrue(identify.call_args.kwargs['allow_upstream_lookup'])


if __name__ == '__main__':
    unittest.main()
