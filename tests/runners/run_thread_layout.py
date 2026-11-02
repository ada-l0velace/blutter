#!/usr/bin/env python3
"""Check runtime layouts without downloading or building a Dart SDK."""
import os
from itertools import combinations
from pathlib import Path
import subprocess
import tempfile


def main():
    root = Path(__file__).resolve().parents[2]
    compiler = os.environ.get('CXX', 'c++')
    source = root / 'tests/unit/thread_layout_test.cpp'
    flags = ['-std=c++20', '-O2', '-Wall', '-Wextra', '-Werror', '-I' + str(root / 'blutter/src')]
    profiles = (None, 'BLUTTER_SHOREBIRD_3C9C', 'BLUTTER_SHOREBIRD_8399', 'BLUTTER_SHOREBIRD_7D8F')
    with tempfile.TemporaryDirectory(prefix='thread-layout-') as temporary:
        for index, profile in enumerate(profiles):
            executable = Path(temporary) / ('layout-' + str(index))
            defines = ['-D' + profile] if profile else []
            subprocess.run([compiler, *flags, *defines, str(source), '-o', str(executable)],
                           check=True, timeout=60)
            subprocess.run([str(executable)], check=True, timeout=15)
        for pair in combinations(profiles[1:], 2):
            conflict = subprocess.run([compiler, *flags, *['-D' + name for name in pair],
                                       '-fsyntax-only', str(source)], capture_output=True, text=True, timeout=60)
            if conflict.returncode == 0 or 'Select only one runtime layout' not in conflict.stderr:
                raise RuntimeError('Conflicting runtime layouts were not rejected')
    print('Conflicting runtime layout flags rejected')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
