"""Check native failure propagation without optional export modes without an SDK."""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from blutter import BlutterInput, build_and_run
from dartvm_fetch_build import DartLibInfo


class AnalysisCliTests(unittest.TestCase):
    def make_input(self, directory):
        info = DartLibInfo('3.13.4', 'android', 'arm64', True, '0' * 32)
        request = BlutterInput('synthetic-input', info, str(directory / 'output'),
                               False, False, False)
        executable = directory / 'synthetic-tool'
        executable.touch()
        request.blutter_file = str(executable)
        return request

    def test_default_calls_native_tool_with_checked_status(self):
        with tempfile.TemporaryDirectory() as temporary:
            request = self.make_input(Path(temporary))
            with patch('blutter.subprocess.run') as run:
                build_and_run(request)
            self.assertNotIn('--allow-partial', run.call_args.args[0])
            self.assertTrue(run.call_args.kwargs['check'])

    def test_export_with_errors_does_not_hide_native_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            request = self.make_input(Path(temporary))
            with patch('blutter.subprocess.run', side_effect=subprocess.CalledProcessError(1, 'synthetic-tool')) as run:
                with self.assertRaises(subprocess.CalledProcessError):
                    build_and_run(request)
            self.assertTrue(run.call_args.kwargs['check'])


if __name__ == '__main__':
    unittest.main()
