import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
import sdk_abi_features as abi
import reader_cache
import dartvm_fetch_build as build
from dartvm_fetch_build import DartLibInfo


class SdkAbiFeatureTests(unittest.TestCase):
    def test_tokens_preserve_literals_and_ignore_comments(self):
        marker = 'int Authored::rule('
        first = 'int Authored::rule(int x) { /* note */ return x + 1; }'
        second = 'int Authored::rule ( int x ) {\n // other comment\n return x+1;\n}'
        self.assertEqual(abi.function_tokens(first, marker), abi.function_tokens(second, marker))
        self.assertNotEqual(abi.fingerprint(abi.function_tokens(first, marker)),
                            abi.fingerprint(abi.function_tokens(first.replace('+ 1', '+ 2'), marker)))
        # Whitespace can change maximal-munch operator tokens, hence semantics.
        self.assertNotEqual(abi.function_tokens('int Authored::rule() { return a+++b; }', marker),
                            abi.function_tokens('int Authored::rule() { return a+ ++b; }', marker))
        literal = 'int Authored::rule() { return "// not a comment"; }'
        self.assertIn('"// not a comment"', abi.function_tokens(literal, marker))
        for bad in ('int Other::rule() { return 0; }', first + first, 'int Authored::rule(int x);', first[:-1], '/*' + first, first + '\n/* unclosed', first + '\n\"unclosed', '// continued comment\\\n' + first):
            with self.assertRaises(ValueError): abi.function_tokens(bad, marker)

    def fixture(self, root):
        policies = {'authored_rule': ('authored.cc', 'int Authored::rule(')}
        directory = root / 'runtime/vm'; directory.mkdir(parents=True)
        source = 'int Authored::rule(int x) { return x + 1; }'
        (directory / 'authored.cc').write_text(source)
        reviewed = {'authored_rule': (abi.fingerprint(abi.function_tokens(source, 'int Authored::rule(')),)}
        return policies, reviewed

    def test_source_gate_and_policy_drift(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); policies, reviewed = self.fixture(root)
            with patch.object(abi, '_POLICIES', policies), patch.object(abi, '_REVIEWED', reviewed):
                cap = abi.inspect_source(root)
                self.assertTrue(abi.valid_capability(cap))
                self.assertIn('=ON', abi.cmake_options(cap)[0])
                self.assertEqual(len(abi.capability_id(cap)), 64)
                with patch.object(abi, '_MAX_SOURCE_BYTES', 8):
                    self.assertIsNone(abi.inspect_source(root))
                with patch.object(abi, '_MAX_TOKENS', 1):
                    self.assertIsNone(abi.inspect_source(root))
                source = root / 'runtime/vm/authored.cc'
                source.write_text(source.read_text().replace('+ 1', '+ 2'))
                self.assertIsNone(abi.inspect_source(root))
                source.unlink(); self.assertIsNone(abi.inspect_source(root))
                bad = copy.deepcopy(cap); bad['schema'] = True
                self.assertFalse(abi.valid_capability(bad))
                bad = copy.deepcopy(cap); bad['fingerprints']['authored_rule'] = 'unknown'
                self.assertFalse(abi.valid_capability(bad))
                self.assertIn('=OFF', abi.cmake_options(None)[0])
                with self.assertRaises(ValueError): abi.capability_id(bad)

    def test_optional_prologue_policies_and_independent_drift(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);policies,reviewed=self.fixture(root)
            text='void Authored::types() { return; } void Authored::parameters() { return; }'
            extra=root/'runtime/vm/prologue.cc';extra.write_text(text)
            type_policy=('prologue.cc','void Authored::types(')
            parameter_policy=('prologue.cc','void Authored::parameters(')
            th=abi.fingerprint(abi.function_tokens(text,type_policy[1]))
            ph=abi.fingerprint(abi.function_tokens(text,parameter_policy[1]))
            with patch.object(abi,'_POLICIES',policies), patch.object(abi,'_REVIEWED',reviewed), \
                 patch.object(abi,'_PROLOGUE_POLICY',type_policy),patch.object(abi,'_PROLOGUE_REVIEWED',(th,)), \
                 patch.object(abi,'_PARAMETER_POLICY',parameter_policy),patch.object(abi,'_PARAMETER_REVIEWED',(ph,)):
                cap=abi.inspect_source(root)
                self.assertTrue(abi.valid_capability(cap))
                self.assertTrue(all(v.endswith('=ON') for v in abi.cmake_options(cap)))
                for key in ('descriptor_prologue','descriptor_parameters'):
                    bad=copy.deepcopy(cap);bad[key]='unreviewed';self.assertFalse(abi.valid_capability(bad))
                extra.write_text(text.replace('parameters() { return; }','parameters() { changed(); }'))
                drift=abi.inspect_source(root)
                self.assertEqual(drift['descriptor_prologue'],th)
                self.assertNotIn('descriptor_parameters',drift)
                self.assertTrue(abi.cmake_options(drift)[-1].endswith('=OFF'))
                extra.unlink();legacy=abi.inspect_source(root)
                self.assertTrue(abi.valid_capability(legacy))
                self.assertEqual(abi.cmake_options(legacy)[1:],['-DBLUTTER_DESCRIPTOR_PROLOGUE=OFF','-DBLUTTER_DESCRIPTOR_PARAMETERS=OFF'])

    def test_capability_receipt_preserves_library_and_binds_headers(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); source_root = root / 'sdk'; policies, reviewed = self.fixture(source_root)
            info = DartLibInfo('9.8.7', 'android', 'arm64', snapshot_hash='1' * 32)
            lib = root / 'packages/lib/libreader.a'; lib.parent.mkdir(parents=True); lib.write_bytes(b'authored library')
            header = root / 'packages/include' / ('dartvm' + info.sdk_key) / 'vm/object.h'
            header.parent.mkdir(parents=True); header.write_text('// authored header\n')
            source = dict(source_revision='2' * 40, source_hash=info.snapshot_hash)
            with patch.object(abi, '_POLICIES', policies), patch.object(abi, '_REVIEWED', reviewed):
                source['call_input_capability'] = abi.inspect_source(source_root)
                reader_cache.write_verified(lib, info, 'runtime', source)
                metadata = reader_cache.read_verified(lib, info, 'runtime')
                self.assertEqual(metadata['call_input_capability'], source['call_input_capability'])
                receipt = reader_cache.metadata_path(lib)
                invalid = copy.deepcopy(metadata); invalid['call_input_capability']['policy'] = 'unknown_policy'
                receipt.write_text(json.dumps(invalid))
                self.assertNotIn('call_input_capability', reader_cache.read_verified(lib, info, 'runtime'))
                reader_cache.write_verified(lib, info, 'runtime', source)
                content = lib.read_bytes()
                with patch.object(build, 'SDK_DIR', str(root / 'absent')), patch.object(build, 'fetch_and_build') as fetch:
                    self.assertEqual(build.refresh_call_input_capability(info, lib, metadata), metadata)
                    fetch.assert_not_called()
                sdk = root / 'dartsdk'; (sdk / ('v' + info.sdk_key)).mkdir(parents=True)
                with patch.object(build, 'SDK_DIR', str(sdk)), patch.object(build, 'verify_dart_sources', return_value=dict(source, call_input_capability=None)), patch.object(build, 'cmake_dart') as rebuild:
                    updated = build.refresh_call_input_capability(info, lib, metadata)
                    self.assertNotIn('call_input_capability', updated)
                    rebuild.assert_not_called()
                self.assertEqual(lib.read_bytes(), content)
                header.write_text('// changed header\n')
                self.assertIsNone(reader_cache.read_verified(lib, info, 'runtime'))

    def test_launcher_rebuilds_only_reader_when_capability_changes(self):
        import blutter
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); policies, reviewed = self.fixture(root / 'sdk')
            with patch.object(abi, '_POLICIES', policies), patch.object(abi, '_REVIEWED', reviewed):
                capability = abi.inspect_source(root / 'sdk')
                for enabling in (True, False):
                    with self.subTest(enabling=enabling):
                        runtime = dict(call_input_capability=capability if enabling else None)
                        old_reader = dict(call_input_capability=None if enabling else capability)
                        item = blutter.BlutterInput('authored.so', DartLibInfo('9.8.7', 'android', 'arm64'), 'authored-out', False, False, False)
                        item.blutter_file = str(root / 'reader')
                        def configure(request):
                            Path(request.blutter_file).write_bytes(b'authored reader')
                            self.assertEqual(abi.cmake_options(request.call_input_capability),
                                             ['-DBLUTTER_FIXED_STACK_INPUTS=' + ('ON' if enabling else 'OFF'), '-DBLUTTER_DESCRIPTOR_PROLOGUE=OFF', '-DBLUTTER_DESCRIPTOR_PARAMETERS=OFF'])
                        with patch.object(blutter, 'read_verified', side_effect=lambda path, info, kind, *args: runtime if kind == 'runtime' else old_reader), \
                             patch.object(build, 'refresh_call_input_capability', return_value=runtime), \
                             patch.object(build, 'fetch_and_build') as fetch, \
                             patch.object(blutter, 'cmake_blutter', side_effect=configure) as cmake, \
                             patch.object(blutter, 'write_verified') as write, patch.object(blutter, 'run_blutter') as run:
                            blutter.build_and_run(item)
                            cmake.assert_called_once(); fetch.assert_not_called(); write.assert_called_once(); run.assert_called_once()
                            self.assertEqual(write.call_args.args[3], runtime)


if __name__ == '__main__': unittest.main()
