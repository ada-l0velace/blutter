"""Authored files and child processes; no vendor binaries or app fixtures."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('vendor_probe', ROOT / 'scripts/probe_shorebird_analyzer.py')
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)


def document():
    return {'metadata': {'word_size': 8, 'compressed_word_size': 4, 'analyzer_version': 2},
            'objects': [
                {'type': 'NoValue'},
                {'id': 1, 'type': 'Class', 'name': 'Sample', 'instance_slots': []},
                {'id': 2, 'type': 'Field', 'name': 'value', 'type_class': 1},
                {'id': 3, 'type': 'Function', 'signature': 'void Sample.run()'},
                {'id': 4, 'type': 'Code', 'offset': 16, 'size': 8,
                 'section': '_kDartIsolateSnapshotInstructions'},
                {'id': 5, 'type': 'ObjectPool', 'references': [0, 16, 1]},
                {'id': 6, 'type': 'String', 'value': 'authored'},
            ]}


@unittest.skipUnless(os.name == 'posix', 'The vendor probe targets macOS files')
class ProbeFiles(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.analyzer = self.root / 'authored-analyzer'
        self.analyzer.write_bytes(b'\xcf\xfa\xed\xfeAuthoredAnalyzer')
        self.analyzer.chmod(0o700)
        self.library = self.root / 'authored.so'
        self.library.write_bytes(b'\x7fELFauthored-input')
        self.output = self.root / 'output'
        self.sentinel = self.root / 'sentinel'
        self.sentinel.write_bytes(b'unchanged')

    def fake_run(self, command, output, timeout):
        (output / 'snapshot.json').write_text(json.dumps(document()))
        (output / 'analyzer.log').write_bytes(b'authored stdout\nauthored stderr\n')
        return 0

    def run_probe(self, runner=None, **arguments):
        with patch.object(probe.sys, 'platform', 'darwin'), \
                patch.object(probe, 'run_analyzer', side_effect=runner or self.fake_run) as called:
            result = probe.probe(arguments.pop('analyzer', self.analyzer),
                                 arguments.pop('library', self.library),
                                 arguments.pop('output', self.output), **arguments)
            return result, called

    def test_success_reports_observations_without_importing_them(self):
        original = self.library.read_bytes()
        result, called = self.run_probe()
        self.assertEqual(result['status'], 'exported_for_review')
        self.assertTrue(all(result['observed_metadata'].values()))
        self.assertEqual(result['input_sha256'], hashlib.sha256(original).hexdigest())
        self.assertEqual(called.call_args.args[0], [str(self.analyzer), '--out=snapshot.json', str(self.library)])
        self.assertEqual(self.library.read_bytes(), original)
        self.assertEqual(self.sentinel.read_bytes(), b'unchanged')
        self.assertEqual({p.name for p in self.output.iterdir()}, {'snapshot.json', 'analyzer.log'})
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o700)

    def test_non_macos_cannot_launch_or_create_output(self):
        with patch.object(probe.sys, 'platform', 'linux'), patch.object(probe, 'run_analyzer') as called:
            with self.assertRaisesRegex(probe.ProbeError, 'only on macOS'):
                probe.probe(self.analyzer, self.library, self.output)
        called.assert_not_called()
        self.assertFalse(self.output.exists())

    def test_existing_output_is_never_reused(self):
        self.output.mkdir()
        existing = self.output / 'snapshot.json'
        existing.write_bytes(b'keep')
        with self.assertRaises(FileExistsError):
            self.run_probe()
        self.assertEqual(existing.read_bytes(), b'keep')

    def test_symlink_output_is_not_followed(self):
        self.output.symlink_to(self.root, target_is_directory=True)
        before = set(self.root.iterdir())
        with self.assertRaises(FileExistsError):
            self.run_probe()
        self.assertEqual(before, set(self.root.iterdir()))
        self.assertEqual(self.sentinel.read_bytes(), b'unchanged')

    def test_symlink_input_or_analyzer_is_not_followed(self):
        for original in (self.library, self.analyzer):
            link = self.root / (original.name + '-link')
            link.symlink_to(original)
            with self.assertRaises(OSError):
                self.run_probe(**{'library' if original == self.library else 'analyzer': link})
        self.assertFalse(self.output.exists())

    def test_directory_or_fifo_cannot_be_an_input(self):
        fifo = self.root / 'fifo'
        os.mkfifo(fifo)
        for path in (self.root, fifo):
            with self.assertRaises(probe.ProbeError):
                self.run_probe(library=path)
        self.assertFalse(self.output.exists())

    def test_wrong_magic_and_missing_execute_permission_stop_before_output(self):
        for payload, mode in ((b'not-macho', 0o700), (b'\xcf\xfa\xed\xfeauthored', 0o600)):
            self.analyzer.write_bytes(payload)
            self.analyzer.chmod(mode)
            with self.assertRaises(probe.ProbeError):
                self.run_probe()
            self.assertFalse(self.output.exists())

    def test_archive_input_is_not_extracted(self):
        self.library.write_bytes(b'PK\x03\x04authored-archive')
        with self.assertRaisesRegex(probe.ProbeError, 'not an APK or archive'):
            self.run_probe()
        self.assertFalse(self.output.exists())

    def test_large_input_is_rejected_before_output(self):
        with patch.object(probe, 'MAX_INPUT_BYTES', 4):
            with self.assertRaises(probe.ProbeError):
                self.run_probe()
        self.assertFalse(self.output.exists())

    def test_analyzer_cannot_also_be_the_input(self):
        with self.assertRaisesRegex(probe.ProbeError, 'different files'):
            self.run_probe(library=self.analyzer)
        self.assertFalse(self.output.exists())

    def test_bad_timeout_is_rejected_before_output(self):
        for timeout in (0, -1, float('nan'), float('inf'), 3601):
            with self.assertRaises(probe.ProbeError):
                self.run_probe(timeout=timeout)
        self.assertFalse(self.output.exists())

    def test_unusual_names_stay_single_arguments(self):
        self.library = self.root / '.input ; $(not-a-command) ü.so'
        self.library.write_bytes(b'\x7fELFauthored')
        self.analyzer = self.root / 'analyzer with spaces'
        self.analyzer.write_bytes(b'\xcf\xfa\xed\xfeauthored')
        self.analyzer.chmod(0o700)
        result, called = self.run_probe()
        self.assertEqual(called.call_args.args[0], [str(self.analyzer), '--out=snapshot.json', str(self.library)])
        self.assertEqual(result['status'], 'exported_for_review')
        self.assertFalse((self.root / 'not-a-command').exists())

    def test_relative_input_and_output_paths_are_made_absolute(self):
        previous = Path.cwd()
        try:
            os.chdir(self.root)
            _, called = self.run_probe(analyzer=Path(self.analyzer.name), library=Path(self.library.name), output=Path('output'))
        finally:
            os.chdir(previous)
        self.assertTrue(all(Path(value).is_absolute() for value in called.call_args.args[0][::2]))

    def test_nonzero_child_status_cannot_be_success(self):
        def failure(command, output, timeout):
            self.fake_run(command, output, timeout)
            return -6
        with self.assertRaisesRegex(probe.ProbeError, 'status -6'):
            self.run_probe(failure)
        self.assertTrue((self.output / 'analyzer.log').exists())

    def test_missing_or_malformed_json_is_preserved_as_failure(self):
        for raw in (b'', b'not-json'):
            def malformed(command, output, timeout):
                (output / 'snapshot.json').write_bytes(raw)
                return 0
            destination = self.root / ('empty-output' if not raw else 'malformed-output')
            with self.assertRaises(probe.ProbeError):
                self.run_probe(malformed, output=destination)
            self.assertEqual((destination / 'snapshot.json').read_bytes(), raw)

    def test_changed_original_input_is_reported(self):
        def changed(command, output, timeout):
            self.fake_run(command, output, timeout)
            self.library.write_bytes(b'\x7fELFchanged')
            return 0
        with self.assertRaisesRegex(probe.ProbeError, 'changed during'):
            self.run_probe(changed)

    def test_replaced_input_path_is_reported(self):
        def replaced(command, output, timeout):
            self.fake_run(command, output, timeout)
            self.library.unlink()
            self.library.write_bytes(b'\x7fELFreplacement')
            return 0
        with self.assertRaisesRegex(probe.ProbeError, 'changed during'):
            self.run_probe(replaced)

    def test_grown_input_is_bounded_before_rehashing(self):
        def grown(command, output, timeout):
            self.fake_run(command, output, timeout)
            with self.library.open('r+b') as stream:
                stream.truncate(65)
            return 0
        with patch.object(probe, 'MAX_INPUT_BYTES', 64):
            with self.assertRaisesRegex(probe.ProbeError, 'size changed'):
                self.run_probe(grown)

    @unittest.skipIf(sys.platform == 'darwin', 'This checks the real unsupported-host CLI path')
    def test_cli_on_linux_never_launches_or_creates_output(self):
        result = subprocess.run([sys.executable, str(ROOT / 'scripts/probe_shorebird_analyzer.py'),
                                 '--analyzer', str(self.analyzer), '--input', str(self.library),
                                 '--output', str(self.output)], capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 1)
        self.assertIn('only on macOS', result.stderr)
        self.assertFalse(self.output.exists())


class ProbeJson(unittest.TestCase):
    def parse(self, raw):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'authored.json'
            path.write_bytes(raw)
            return probe.summarize_json(path)

    def test_valid_schema_and_missing_capabilities_are_distinguished(self):
        value = document()
        result = self.parse(json.dumps(value).encode())
        self.assertTrue(all(result['observed_metadata'].values()))
        value['objects'] = [{'type': 'NoValue'}]
        result = self.parse(json.dumps(value).encode())
        self.assertFalse(any(result['observed_metadata'].values()))
        self.assertIn('not a sandbox', result['limits'])

    def test_unknown_types_are_counted_without_printing_their_text(self):
        value = document()
        value['objects'].extend([{}, {'id': 7, 'type': '\x1b[31mAuthored'}])
        result = probe.summarize_document(value)
        self.assertEqual(result['counts']['other'], 2)
        self.assertNotIn('\x1b', json.dumps(result))

    def test_duplicate_keys_and_nonstandard_numbers_are_rejected(self):
        for raw in (b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":Infinity}', b'{"a":1e999}',
                    b'{"a":18446744073709551616}', b'{"a":' + b'9' * 100 + b'}'):
            with self.subTest(raw=raw[:40]), self.assertRaises(probe.ProbeError):
                self.parse(raw)

    def test_invalid_utf8_and_json_are_rejected(self):
        for raw in (b'\xff', b'{} trailing', b'{"a":', b'[]', b'null'):
            with self.assertRaises(probe.ProbeError):
                self.parse(raw)

    def test_depth_limit_and_brackets_inside_strings(self):
        with self.assertRaisesRegex(probe.ProbeError, 'nesting'):
            self.parse(b'[' * 65 + b'0' + b']' * 65)
        value = document()
        value['extra'] = '[' * 100 + '\\"' + ']' * 100
        self.parse(json.dumps(value).encode())

    def test_item_and_byte_limits(self):
        with patch.object(probe, 'MAX_JSON_ITEMS', 2):
            with self.assertRaisesRegex(probe.ProbeError, 'item count'):
                self.parse(b'[0,0,0,0]')
        with patch.object(probe, 'MAX_JSON_BYTES', 4):
            with self.assertRaises(probe.ProbeError):
                self.parse(b'{"a":1}')

    def test_metadata_types_and_sizes_are_checked(self):
        for key, bad in (('word_size', True), ('word_size', 16), ('compressed_word_size', 2),
                         ('analyzer_version', 0), ('analyzer_version', '2')):
            value = document()
            value['metadata'][key] = bad
            with self.assertRaises(probe.ProbeError):
                probe.summarize_document(value)

    def test_duplicate_and_invalid_object_ids_are_rejected(self):
        for bad in (0, -1, True, 1):
            value = document()
            value['objects'].append({'type': 'Null', 'id': bad})
            with self.assertRaises(probe.ProbeError):
                probe.summarize_document(value)

    def test_code_ranges_cannot_overflow_or_use_booleans(self):
        for offset, size in ((-1, 8), (True, 8), ((1 << 64) - 1, 8), (16, -1)):
            value = document()
            value['objects'][4].update(offset=offset, size=size)
            with self.assertRaises(probe.ProbeError):
                probe.summarize_document(value)

    def test_object_pool_shape_and_object_limit(self):
        value = document()
        value['objects'][5]['references'] = [1, 2]
        with self.assertRaises(probe.ProbeError):
            probe.summarize_document(value)
        with patch.object(probe, 'MAX_OBJECTS', 2):
            with self.assertRaises(probe.ProbeError):
                probe.summarize_document(document())

    def test_authored_json_header_bit_mutations_do_not_escape_validation(self):
        raw = json.dumps(document()).encode()
        for offset in range(64):
            for bit in range(8):
                changed = bytearray(raw)
                changed[offset] ^= 1 << bit
                try:
                    result = self.parse(bytes(changed))
                except probe.ProbeError:
                    continue
                self.assertEqual(result['status'], 'exported_for_review')


@unittest.skipUnless(os.name == 'posix', 'Process-group controls require POSIX')
class ProbeRunner(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.output = self.root / 'output'
        self.output.mkdir()
        self.sentinel = self.root / 'sentinel'
        self.sentinel.write_bytes(b'unchanged')
        self.children = []
        original = probe.subprocess.Popen
        def capture(*arguments, **keywords):
            process = original(*arguments, **keywords)
            self.children.append(process)
            return process
        tracking = patch.object(probe.subprocess, 'Popen', side_effect=capture)
        tracking.start()
        self.addCleanup(tracking.stop)

    def tearDown(self):
        for child in self.children:
            if child.poll() is None:
                probe.kill_group(child)
                child.wait(timeout=5)
                self.fail('The runner left its child alive')

    def run_program(self, text, timeout=2):
        script = self.root / 'authored.py'
        script.write_text(text)
        return probe.run_analyzer([sys.executable, str(script)], self.output, timeout)

    def test_stdout_stderr_and_json_are_retained(self):
        text = ('import json, pathlib, sys\n'
                'print("authored stdout")\nprint("authored stderr", file=sys.stderr)\n'
                f'pathlib.Path("snapshot.json").write_text({json.dumps(document())!r})\n')
        self.assertEqual(self.run_program(text), 0)
        log = (self.output / 'analyzer.log').read_bytes()
        self.assertIn(b'authored stdout', log)
        self.assertIn(b'authored stderr', log)
        self.assertEqual(stat.S_IMODE((self.output / 'analyzer.log').stat().st_mode), 0o600)
        self.assertEqual(probe.summarize_json(self.output / 'snapshot.json')['status'], 'exported_for_review')

    def test_timeout_kills_the_child(self):
        started = time.monotonic()
        with self.assertRaisesRegex(probe.ProbeError, 'timed out'):
            self.run_program('import time\nprint("started", flush=True)\ntime.sleep(20)\n', timeout=0.25)
        self.assertLess(time.monotonic() - started, 5)
        self.assertIn(b'started', (self.output / 'analyzer.log').read_bytes())
        self.assertIsNotNone(self.children[0].poll())

    def test_log_flood_is_capped(self):
        with patch.object(probe, 'MAX_LOG_BYTES', 256):
            with self.assertRaisesRegex(probe.ProbeError, 'log exceeds'):
                self.run_program('import os\nos.write(1, b"x" * 10000)\n')
        self.assertEqual((self.output / 'analyzer.log').stat().st_size, 256)

    def test_json_growth_stops_the_child(self):
        with patch.object(probe, 'MAX_JSON_BYTES', 256):
            with self.assertRaisesRegex(probe.ProbeError, 'JSON output exceeds'):
                self.run_program('import pathlib, time\npathlib.Path("snapshot.json").write_bytes(b"x" * 10000)\ntime.sleep(20)\n')

    def test_json_symlink_is_not_read_or_truncated_by_the_probe(self):
        text = ('import pathlib\np = pathlib.Path("snapshot.json")\np.unlink()\n'
                f'p.symlink_to({str(self.sentinel)!r})\n')
        with self.assertRaisesRegex(probe.ProbeError, 'not a regular file'):
            self.run_program(text)
        self.assertEqual(self.sentinel.read_bytes(), b'unchanged')

    def test_no_shell_or_loader_environment_is_inherited(self):
        text = ('import os, pathlib, sys\n'
                'pathlib.Path("snapshot.json").write_text(str(os.environ.get("DYLD_INSERT_LIBRARIES")))\n'
                'print(sys.argv)\n')
        script = self.root / 'script ; not-shell.py'
        script.write_text(text)
        with patch.dict(os.environ, {'DYLD_INSERT_LIBRARIES': '/not/a/library'}):
            self.assertEqual(probe.run_analyzer([sys.executable, str(script), '$(not-a-command)'], self.output, 2), 0)
        self.assertEqual((self.output / 'snapshot.json').read_text(), 'None')
        self.assertIn(b'$(not-a-command)', (self.output / 'analyzer.log').read_bytes())
        self.assertFalse((self.root / 'not-a-command').exists())

    def test_setup_failure_leaves_no_owned_child(self):
        with patch.object(probe.selectors, 'DefaultSelector', side_effect=RuntimeError('authored setup failure')):
            with self.assertRaises(RuntimeError):
                self.run_program('import time\ntime.sleep(20)\n')
        self.assertIsNotNone(self.children[0].poll())
        self.assertEqual(self.sentinel.read_bytes(), b'unchanged')

    def test_parent_exit_does_not_leave_a_pipe_holding_child_running(self):
        marker = self.root / 'late-marker'
        text = ('import os, pathlib, time\n'
                'child = os.fork()\n'
                'if child == 0:\n'
                '    time.sleep(0.5)\n'
                f'    pathlib.Path({str(marker)!r}).write_text("must not happen")\n'
                '    os._exit(0)\n'
                'os._exit(0)\n')
        self.assertEqual(self.run_program(text), 0)
        time.sleep(0.6)
        self.assertFalse(marker.exists())

    def test_keyboard_interrupt_cleans_up_the_child(self):
        selector = unittest.mock.Mock()
        selector.select.side_effect = KeyboardInterrupt
        with patch.object(probe.selectors, 'DefaultSelector', return_value=selector):
            with self.assertRaises(KeyboardInterrupt):
                self.run_program('import time\ntime.sleep(20)\n')
        self.assertIsNotNone(self.children[0].poll())
        selector.close.assert_called_once()


if __name__ == '__main__':
    unittest.main()
