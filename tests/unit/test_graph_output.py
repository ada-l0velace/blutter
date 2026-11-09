"""Authored controls for graph packaging, query loading and error propagation."""
import gzip
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'scripts'))
from graph_output import compress_graph, run_blutter
from graph_io import load_graph, require_full_evidence


class GraphOutputTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.path = self.directory / 'snapshot_calls.json'

    def command(self, body):
        return [sys.executable, '-c', body, str(self.directory)]

    def test_compression_preserves_exact_bytes_and_unicode(self):
        raw = json.dumps({'label': 'a λ function', 'bits': (1 << 64) - 1}, ensure_ascii=False).encode()
        self.path.write_bytes(raw)
        compressed = compress_graph(self.path)
        self.assertFalse(self.path.exists())
        self.assertEqual(gzip.decompress(compressed.read_bytes()), raw)
        self.assertEqual(load_graph(self.directory), json.loads(raw))
        self.assertEqual(load_graph(compressed), json.loads(raw))

    def test_compression_is_reproducible(self):
        raw = b'{"value":42}\n'
        self.path.write_bytes(raw)
        first = compress_graph(self.path).read_bytes()
        self.path.write_bytes(raw)
        self.assertEqual(compress_graph(self.path).read_bytes(), first)

    def test_failed_write_retains_plain_and_previous_compressed_graph(self):
        self.path.write_bytes(b'{"value":1}')
        destination = Path(str(self.path) + '.gz')
        destination.write_bytes(b'previous export')
        with patch('graph_output.shutil.copyfileobj', side_effect=OSError('disk full')):
            with self.assertRaises(OSError):
                compress_graph(self.path)
        self.assertEqual(self.path.read_bytes(), b'{"value":1}')
        self.assertEqual(destination.read_bytes(), b'previous export')
        self.assertEqual(sorted(p.name for p in self.directory.iterdir()),
                         ['snapshot_calls.json', 'snapshot_calls.json.gz'])

    def test_failed_publication_retains_source(self):
        self.path.write_bytes(b'{}')
        with patch('graph_output.os.replace', side_effect=OSError('publication failed')):
            with self.assertRaises(OSError):
                compress_graph(self.path)
        self.assertEqual(list(self.directory.iterdir()), [self.path])

    def test_plain_directory_lookup_and_old_format(self):
        self.path.write_text('{"format":28}')
        Path(str(self.path) + '.gz').write_bytes(b'old invalid archive')
        self.assertEqual(load_graph(self.directory, require_full=True), {'format': 28})

    def test_full_evidence_is_required_explicitly(self):
        graph = {'format': 31, 'export': {'detail': 'compact',
                 'omitted': ['receiver_blocks', 'call_effect_states']}}
        self.path.write_text(json.dumps(graph))
        self.assertEqual(load_graph(self.path), graph)
        with self.assertRaisesRegex(ValueError, '--graph-detail full'):
            load_graph(self.path, require_full=True)
        require_full_evidence({'format': 31, 'export': {'detail': 'full', 'omitted': []}})

    def test_invalid_evidence_metadata_is_rejected(self):
        for export in (None, [], {'detail': 'unknown'}, {'detail': 'full', 'omitted': ['receiver_blocks']}):
            with self.subTest(export=export), self.assertRaises(ValueError):
                require_full_evidence({'format': 31, 'export': export})

    def test_compressed_size_limit_applies_after_decompression(self):
        self.path.write_bytes(b'{"label":"' + b'a' * 2000 + b'"}')
        compressed = compress_graph(self.path)
        self.assertLess(compressed.stat().st_size, 100)
        with self.assertRaisesRegex(ValueError, 'uncompressed'):
            load_graph(compressed, max_bytes=100)
        self.assertEqual(len(load_graph(compressed, max_bytes=2100)['label']), 2000)

    def test_truncated_and_invalid_compressed_graphs_fail(self):
        path = Path(str(self.path) + '.gz')
        for raw in (b'bad gzip', gzip.compress(b'{}')[:-4]):
            path.write_bytes(raw)
            with self.subTest(raw=raw), self.assertRaises((OSError, EOFError)):
                load_graph(path)
        path.write_bytes(gzip.compress(b'[]'))
        with self.assertRaisesRegex(ValueError, 'JSON object'):
            load_graph(path)

    def test_successful_native_export_can_be_compressed(self):
        run_blutter(self.command('from pathlib import Path; import sys; '
                    '(Path(sys.argv[1])/"snapshot_calls.json").write_text("{}")'), self.directory, True)
        self.assertEqual(load_graph(self.directory), {})
        self.assertFalse(self.path.exists())

    def test_partial_export_is_compressed_and_exit_code_preserved(self):
        command = self.command('from pathlib import Path; import sys; p=Path(sys.argv[1]); '
                               '(p/"snapshot_calls.json").write_text("{}"); '
                               '(p/"analysis_status.json").write_text(\'{"status":"partial"}\'); sys.exit(7)')
        with self.assertRaises(subprocess.CalledProcessError) as raised:
            run_blutter(command, self.directory, True)
        self.assertEqual(raised.exception.returncode, 7)
        self.assertEqual(load_graph(self.directory), {})
        self.assertFalse(self.path.exists())

    def test_fatal_failure_does_not_package_stale_partial_export(self):
        self.path.write_bytes(b'{}')
        (self.directory / 'analysis_status.json').write_text('{"status":"partial"}')
        with self.assertRaises(subprocess.CalledProcessError):
            run_blutter(self.command('import sys; sys.exit(9)'), self.directory, True)
        self.assertTrue(self.path.exists())
        self.assertFalse(Path(str(self.path) + '.gz').exists())

    def test_no_new_graph_is_valid_for_older_native_profiles(self):
        self.path.write_bytes(b'{}')
        run_blutter(self.command('pass'), self.directory, True)
        self.assertTrue(self.path.exists())

    def test_packaging_failure_cannot_hide_analysis_failure(self):
        command = self.command('from pathlib import Path; import sys; p=Path(sys.argv[1]); '
                               '(p/"snapshot_calls.json").write_text("{}"); '
                               '(p/"analysis_status.json").write_text(\'{"status":"partial"}\'); sys.exit(7)')
        with patch('graph_output.compress_graph', side_effect=OSError('disk full')):
            with self.assertRaises(subprocess.CalledProcessError) as raised:
                run_blutter(command, self.directory, True)
        self.assertEqual(raised.exception.returncode, 7)
        self.assertTrue(self.path.exists())

    def test_packaging_failure_after_success_is_an_error(self):
        command = self.command('from pathlib import Path; import sys; '
                               '(Path(sys.argv[1])/"snapshot_calls.json").write_text("{}")')
        with patch('graph_output.compress_graph', side_effect=OSError('disk full')):
            with self.assertRaises(OSError):
                run_blutter(command, self.directory, True)
        self.assertTrue(self.path.exists())


if __name__ == '__main__':
    unittest.main()
