#!/usr/bin/env python3
"""Check table feature selection without building a Dart SDK."""
import os
from pathlib import Path
import subprocess
import tempfile


def main():
    root = Path(__file__).resolve().parents[2]
    compiler = os.environ.get('CXX', 'c++')
    source = root / 'tests/unit/runtime_features_test.cpp'
    flags = ['-std=c++20', '-O2', '-Wall', '-Wextra', '-Werror', '-I' + str(root / 'blutter/src')]
    cases = (([], 0), (['HAS_INSTRUCTIONS_TABLE_RODATA'], 1),
             (['BLUTTER_SHOREBIRD_3C9C'], 1), (['BLUTTER_SHOREBIRD_8399'], 0),
             (['BLUTTER_SHOREBIRD_7D8F'], 0),
             (['BLUTTER_SHOREBIRD_3C9C', 'HAS_INSTRUCTIONS_TABLE_RODATA'], 1),
             (['BLUTTER_SHOREBIRD_8399', 'HAS_INSTRUCTIONS_TABLE_RODATA'], 1),
             (['BLUTTER_AUTHORED_PROFILE'], 0), (['HAS_INSTRUCTIONS_TABLE_RODATA=0'], 1),
             (['HAS_INSTRUCTIONS_TABLE_RODATA=1'], 1))
    with tempfile.TemporaryDirectory(prefix='runtime-features-') as temporary:
        for index, (defines, expected) in enumerate(cases):
            executable = Path(temporary) / ('features-' + str(index))
            arguments = [compiler, *flags, *['-D' + value for value in defines]]
            subprocess.run([*arguments, '-DEXPECT_TABLE_SUPPORT=' + str(expected), str(source),
                            '-o', str(executable)], check=True, timeout=60)
            subprocess.run([str(executable)], check=True, timeout=15)
            if index < 2:
                wrong = subprocess.run([*arguments, '-DEXPECT_TABLE_SUPPORT=' + str(1 - expected),
                                        '-fsyntax-only', str(source)], capture_output=True, text=True, timeout=60)
                if wrong.returncode == 0 or 'Unexpected table support' not in wrong.stderr:
                    raise RuntimeError('Incorrect table-support expectation was not rejected')
    print('Ten table configurations and both incorrect-expectation controls passed')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
