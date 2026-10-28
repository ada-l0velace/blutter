#!/usr/bin/env python3
"""Exercise ARM64 provenance safety without a Dart VM (requires C++20, llvm-mc, Capstone)."""
import json
import os
from pathlib import Path
import shlex
import re
import shutil
import subprocess
import sys
import tempfile


def main():
    root = Path(__file__).resolve().parents[2]
    assembler = next((path for name in ['llvm-mc'] + [f'llvm-mc-{v}' for v in range(25, 13, -1)]
                      if (path := shutil.which(name))), None)
    assert assembler, 'llvm-mc is required to assemble independent ARM64 fixtures'
    passed = []
    with tempfile.TemporaryDirectory(prefix='snapshot-annotations-') as temporary:
        temp = Path(temporary)
        executable = temp / 'analyzer'
        flags = shlex.split(subprocess.check_output(
            ['pkg-config', '--cflags', '--libs', 'capstone'], text=True))
        subprocess.run([os.environ.get('CXX', 'g++'), '-std=c++20', '-O1', '-g',
                        '-fsanitize=address,undefined', '-fno-omit-frame-pointer', '-fno-sanitize-recover=all',
                        '-I' + str(root / 'blutter/src'),
                        str(root / 'tests/unit/snapshot_annotations_test.cpp'),
                        str(root / 'blutter/src/SnapshotCodeAnalysis.cpp'),
                        '-o', str(executable)] + flags, check=True)

        def run(name, assembly, extra=None, suffix=b''):
            blocks = {0x1000: assembly, 0x2000: ['ret']}
            blocks.update(extra or {})
            command = [str(executable), str(temp / 'out.json')]
            for address, source in sorted(blocks.items()):
                code = bytearray()
                for instruction in source:
                    # LLVM takes a relative immediate; fixture branch addresses
                    # are absolute to keep entry-point tests easy to read.
                    if instruction.startswith(('bl ', 'b ', 'cbz ', 'cbnz ', 'tbz ', 'tbnz ', 'b.')):
                        instruction = re.sub(r'0x[0-9a-f]+$', lambda m: str(int(m[0], 16) - address - len(code)), instruction)
                    encoded = subprocess.check_output(
                        [assembler, '-triple=aarch64', '-show-encoding'], input=instruction, text=True)
                    encoding = re.search(r'encoding: \[(.*?)\]', encoded)[1]
                    raw = bytes(int(x.strip(), 16) for x in encoding.split(','))
                    assert len(raw) == 4, (instruction, encoded)
                    code.extend(raw)
                if address == 0x1000:
                    code.extend(suffix)
                binary = temp / (str(address) + '.bin')
                binary.write_bytes(code)
                command.extend([hex(address), str(binary)])
            leaks = '1' if sys.platform.startswith('linux') else '0'
            subprocess.run(command, check=True, env=dict(os.environ,
                ASAN_OPTIONS=f'halt_on_error=1:detect_leaks={leaks}', UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1'))
            result = json.loads((temp / 'out.json').read_text())
            passed.append(name)
            return result

        d = run('direct-and-interior-targets', ['bl 0x2000', 'bl 0x2004', 'b 0x3000'])
        assert [e['target'] for e in d['edges']] == [0x2000, 0x2004, 0x3000]
        assert d['edges'][0]['target_label'] == 'known_function'
        assert d['edges'][1]['target_payload'] is None  # end is exclusive
        d = run('target-inside-payload', ['bl 0x2004'], {0x2000: ['nop', 'ret']})
        assert d['edges'][0]['target_payload'] == 0x2000 and d['edges'][0]['target'] == 0x2004
        d = run('derived-pool-and-pair', ['add x16, x27, #1, lsl #12', 'mov x17, x16', 'ldp x0, x1, [x17, #16]'])
        assert [(r['offset'], r['pool_index'], r['proof']) for r in d['references']] == [
            (0x1010, 512, [0x1000, 0x1004]), (0x1018, 513, [0x1000, 0x1004])], d['references']
        d = run('subtraction', ['add x16, x27, #32', 'sub x16, x16, #16', 'ldr x0, [x16]'])
        assert d['references'][0]['pool_index'] == 0
        d = run('thread-indirect-call', ['ldr x16, [x26, #0x78]', 'blr x16'])
        assert d['references'][0]['field_name'] == 'known_thread_field'
        assert d['edges'][0]['target'] is None and d['edges'][0]['via_offset'] == 0x78
        assert d['edges'][0]['proof'] == [0x1000]
        d = run('pool-indirect-call', ['ldr x16, [x27, #16]', 'blr x16'])
        assert d['edges'][0]['target'] is None and d['edges'][0]['via_kind'] == 'pool'
        for name, middle in [
            ('32bit-clobber', ['mov w16, #0']),
            ('movk-clobber', ['movk x16, #1']),
            ('call-clobber', ['bl 0x2000']),
            ('branch-join', ['cbz x0, 0x1008']),
            ('writeback-clobber', ['ldr x0, [x16], #8']),
        ]:
            d = run(name, ['mov x16, x27'] + middle + ['ldr x1, [x16, #16]'])
            assert not d['references'], (name, d['references'])
        d = run('incoming-cross-payload-join', ['mov x16, x27', 'nop', 'ldr x0, [x16, #16]'],
                {0x3000: ['b 0x1008']})
        assert not d['references']
        d = run('indexed-address-unknown', ['ldr x0, [x27, x1]'])
        assert not d['references']
        d = run('narrow-and-unaligned-values-unknown', ['ldr w0, [x27, #16]', 'ldur x1, [x27, #17]'])
        assert len(d['references']) == 2 and all(r['pool_index'] is None for r in d['references'])
        d = run('unknown-thread-field', ['ldr x0, [x26, #0x80]'])
        assert d['references'][0]['field_name'] == ''
        d = run('reserved-base-written', ['ldr x0, [x27, #16]', 'mov x27, x1', 'ldr x0, [x27, #16]'])
        assert not d['references']
        d = run('no-cross-payload-state', ['mov x16, x27'], {0x2000: ['ldr x0, [x16, #16]', 'ret']})
        assert not d['references']
        d = run('indirect-value-clobber', ['ldr x16, [x26, #0x78]', 'mov w16, #0', 'blr x16'])
        assert d['edges'][0]['target'] is None and d['edges'][0]['via_offset'] is None
        d = run('incomplete-decode', ['ldr x0, [x27, #16]'], suffix=b'\xff' * 4)
        assert not d['nodes'][0]['decoded'] and not d['references']
        print(json.dumps({'status': 'PASSED', 'sanitizers': ['address', 'undefined'],
                          'cases': passed, 'case_count': len(passed)}, indent=2))


if __name__ == '__main__':
    main()
