"""Authored CLI address validation and native argument forwarding."""
import argparse
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
import blutter
from dartvm_fetch_build import DartLibInfo


class AnalysisSelection(unittest.TestCase):
    def test_addresses_are_strict_aligned_unsigned_values(self):
        for text in ('0x1000', '0X1000', '4096'):
            self.assertEqual(blutter.analysis_caller_address(text), 4096)
        for text in ('', '0', '-4', '+4', '0x', '0x1001', ' 4096', '4096 ',
                     '1_000', '0x1000junk', '18446744073709551616'):
            with self.subTest(text=text), self.assertRaises(argparse.ArgumentTypeError):
                blutter.analysis_caller_address(text)

    def test_native_command_preserves_selection_and_default(self):
        for selected in (None, 0x1000):
            item = SimpleNamespace(blutter_file='reader', rebuild_blutter=False, create_vs_sln=False,
                                   libapp_path='input library', outdir='output directory', analysis_caller=selected,
                                   dart_info=DartLibInfo('3.11.0', 'android', 'arm64', True, '0' * 32), no_analysis=False)
            with patch.object(blutter, 'read_verified', return_value={'synthetic': True}), patch.object(blutter.subprocess, 'run') as run:
                blutter.build_and_run(item)
            expected = ['reader', '-i', 'input library', '-o', 'output directory']
            if selected is not None:
                expected += ['--analysis-caller', '0x1000']
            run.assert_called_once_with(expected, check=True)


if __name__ == '__main__':
    unittest.main()
