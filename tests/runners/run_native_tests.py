#!/usr/bin/env python3
"""Configure optional C++ tests against an already prepared Dart runtime package."""
import argparse
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
import blutter

TESTS = ('arm64_analyzer_test', 'arm64_decoder_test', 'arm64_boxing_test',
         'arm64_patterns_test', 'analysis_diagnostics_test', 'snapshot_code_ranges_test', 'read_unaligned_test')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--version', required=True, help='Dart SDK version used by the prepared package')
    parser.add_argument('--sdk-key', help='Prepared package key; defaults to the SDK version')
    parser.add_argument('--packages', type=Path, default=ROOT / 'packages')
    parser.add_argument('--build-dir', type=Path, required=True, help='Use a fresh directory for coverage measurements')
    parser.add_argument('--mode', choices=('release', 'sanitize', 'coverage'), default='release')
    parser.add_argument('--jobs', type=int, default=2)
    parser.add_argument('--memcheck', action='store_true', help='Run separate ordinary binaries under Valgrind')
    args = parser.parse_args()
    key = args.sdk_key or args.version
    if not re.fullmatch(r'[A-Za-z0-9_.-]+', key) or args.jobs < 1:
        parser.error('invalid SDK key or job count')
    if args.memcheck and args.mode != 'release':
        parser.error('Memcheck requires separate ordinary release binaries')
    if args.memcheck and not shutil.which('valgrind'):
        parser.error('Valgrind is required for the requested Memcheck lane')
    packages = args.packages.resolve()
    library = f'dartvm{key}_android_arm64'
    package = packages / 'lib/cmake' / library
    if not (packages / 'include' / f'dartvm{key}').is_dir() or not package.is_dir():
        parser.error('matching Dart headers/library are missing; prepare the runtime package first')
    build = args.build_dir.resolve()
    if build in (ROOT, ROOT / 'blutter', packages):
        parser.error('choose a separate build directory')
    blutter.PKG_INC_DIR = str(packages / 'include')
    command = ['cmake', '-S', str(ROOT / 'blutter'), '-B', str(build), '-GNinja',
               f'-DDARTLIB={library}', f'-D{library}_DIR={package}',
               '-DCMAKE_EXPORT_COMPILE_COMMANDS=ON', '-DBLUTTER_BUILD_TESTS=ON',
               '-DCMAKE_BUILD_TYPE=' + ('Release' if args.mode == 'release' else 'Debug'),
               '-DBLUTTER_TEST_SANITIZERS=' + ('ON' if args.mode == 'sanitize' else 'OFF'),
               '-DBLUTTER_TEST_COVERAGE=' + ('ON' if args.mode == 'coverage' else 'OFF')]
    command += blutter.find_compat_macro(args.version, False, key)
    environment = dict(os.environ)
    if args.mode == 'sanitize':
        # LeakSanitizer is measured on Linux. Do not claim it on unsupported hosts.
        leaks = '1' if sys.platform.startswith('linux') else '0'
        environment['ASAN_OPTIONS'] = f'halt_on_error=1:detect_leaks={leaks}'
        environment['UBSAN_OPTIONS'] = 'halt_on_error=1:print_stacktrace=1'
        print(f'ASan/UBSan enabled; leak checking={leaks}; cached Dart runtime is not instrumented', flush=True)
    subprocess.run(command, check=True, env=environment)
    subprocess.run(['cmake', '--build', str(build), '--parallel', str(args.jobs)], check=True, env=environment)
    subprocess.run(['ctest', '--test-dir', str(build), '--output-on-failure'], check=True, env=environment)
    if args.memcheck:
        for name in TESTS:
            subprocess.run(['valgrind', '--error-exitcode=97', '--leak-check=full',
                            '--show-leak-kinds=all', '--errors-for-leak-kinds=definite,indirect,possible',
                            str(build / 'tests' / name)], check=True, env=environment)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
