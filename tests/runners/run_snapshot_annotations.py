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
import argparse
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
import capstone
from check_receiver_analysis import check_receivers


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--memcheck', action='store_true', help='Use ordinary binaries under Valgrind instead of sanitizers')
    args = parser.parse_args()
    if args.memcheck and not shutil.which('valgrind'):
        parser.error('Valgrind is required')
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
        instrumentation = [] if args.memcheck else ['-fsanitize=address,undefined', '-fno-sanitize-recover=all']
        subprocess.run([os.environ.get('CXX', 'g++'), '-std=c++20', '-O1', '-g', '-fno-omit-frame-pointer'] + instrumentation + [
                        '-I' + str(root / 'blutter/src'),
                        str(root / 'tests/unit/snapshot_annotations_test.cpp'),
                        str(root / 'blutter/src/SnapshotCodeAnalysis.cpp'),
                        str(root / 'blutter/src/ReceiverAnalysis.cpp'),
                        '-o', str(executable)] + flags, check=True)

        def run(name, assembly, extra=None, suffix=b''):
            blocks = {0x1000: assembly, 0x2000: ['ret']}
            blocks.update(extra or {})
            blocks = {address: source for address, source in blocks.items() if source is not None}
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
            if args.memcheck:
                command = ['valgrind', '--quiet', '--error-exitcode=97', '--leak-check=full',
                           '--errors-for-leak-kinds=definite,indirect,possible'] + command
            subprocess.run(command, check=True, env=dict(os.environ,
                ASAN_OPTIONS=f'halt_on_error=1:detect_leaks={leaks}', UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1'))
            result = json.loads((temp / 'out.json').read_text())
            # The checker verifies inductive invariants instead of reproducing the
            # native worklist solver. Its bytes come from the assembler fixtures.
            decoder = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
            decoder.detail = True
            fixture_bytes = {address: (temp / (str(address) + '.bin')).read_bytes() for address in blocks}
            def read(address, length):
                return fixture_bytes[address][:length]
            check_receivers(result, read, lambda raw, address: list(decoder.disasm(raw, address)),
                            {'pool_heap_classes': [[3, 1], [4, 1], [5, 2]], 'class_allocations': [[0x2000, 1]]})
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
        d = run('typed-pool-code-entry', ['ldr x30, [x27, #32]', 'ldur x30, [x30, #7]', 'blr x30'])
        edge = d['edges'][0]
        assert edge['target'] is None and edge['snapshot_target'] == 0x2000
        assert (edge['via_kind'], edge['via_offset'], edge['via_field_offset'], edge['proof']) == ('pool_code_entry', 32, 7, [0x1000, 0x1004])
        d = run('copied-unchecked-code-entry', ['add x16, x27, #32', 'ldr x1, [x16]', 'mov x2, x1', 'ldur x3, [x2, #15]', 'mov x4, x3', 'blr x4'])
        assert d['edges'][0]['snapshot_target'] == 0x2004
        assert d['edges'][0]['proof'] == [0x1000, 0x1004, 0x1008, 0x100c, 0x1010]
        for name, assembly in [
            ('untyped-pool-object', ['ldr x30, [x27, #16]', 'ldur x30, [x30, #7]', 'blr x30']),
            ('wrong-code-field', ['ldr x30, [x27, #32]', 'ldur x30, [x30, #23]', 'blr x30']),
            ('narrow-code-entry', ['ldr x30, [x27, #32]', 'ldur w30, [x30, #7]', 'blr x30']),
            ('code-entry-cross-call', ['ldr x30, [x27, #32]', 'bl 0x2000', 'ldur x30, [x30, #7]', 'blr x30']),
            ('code-entry-clobber', ['ldr x30, [x27, #32]', 'ldur x30, [x30, #7]', 'mov w30, #0', 'blr x30']),
            ('code-entry-cross-join', ['ldr x30, [x27, #32]', 'cbz x0, 0x1008', 'ldur x30, [x30, #7]', 'blr x30']),
        ]:
            d = run(name, assembly)
            assert d['edges'][-1]['snapshot_target'] is None
        d = run('indexed-dispatch', ['ldr x30, [x21, x30, lsl #3]', 'blr x30'])
        edge = d['edges'][0]
        assert (edge['via_kind'], edge['via_offset'], edge['index_register'], edge['proof']) == ('dispatch_table', 0, 'x30', [0x1000])
        assert edge['snapshot_target'] is None and edge['target'] is None
        d = run('copied-dispatch-base', ['add x16, x21, #8', 'ldr x17, [x16, x0, lsl #3]', 'mov x30, x17', 'blr x30'])
        assert d['edges'][0]['via_offset'] == 8 and d['edges'][0]['proof'] == [0x1000, 0x1004, 0x1008]
        for name, assembly in [
            ('dispatch-base-written', ['ldr x30, [x21, x0, lsl #3]', 'mov x21, x1', 'blr x30']),
            ('wrong-dispatch-scale', ['ldr x30, [x21, x0]', 'blr x30']),
            ('extended-dispatch-index', ['ldr x30, [x21, w0, uxtw #3]', 'blr x30']),
            ('narrow-dispatch-load', ['ldr w30, [x21, x0, lsl #2]', 'blr x30']),
        ]:
            d = run(name, assembly)
            assert not d['edges'][0]['via_kind']

        def constants(data, edge=0):
            return {r['register']: int(r['bits'], 16) for r in data['edges'][edge]['register_constants']}

        d = run('constant-moves-and-zero-extension', ['mov x0, #-1', 'mov w1, #-1', 'mov x2, x0', 'mov w3, w0', 'mov x4, xzr', 'mov w5, wzr', 'bl 0x2000'])
        assert constants(d) == {'x0': 0xffffffffffffffff, 'x1': 0xffffffff, 'x2': 0xffffffffffffffff, 'x3': 0xffffffff, 'x4': 0, 'x5': 0}
        d = run('wide-immediates', ['movz x0, #0x1234, lsl #48', 'movk x0, #0xabcd, lsl #16', 'movk x0, #0x5678', 'movn w1, #0x1234, lsl #16', 'movk w1, #0x9876', 'bl 0x2000'])
        assert constants(d) == {'x0': 0x12340000abcd5678, 'x1': 0xedcb9876}
        assert d['edges'][0]['register_constants'][0]['proof'] == [0x1000, 0x1004, 0x1008]
        d = run('movk-needs-known-value', ['movk x0, #1', 'movk w1, #2', 'blr x2'])
        assert not constants(d)
        d = run('constant-unknown-write', ['mov x0, #1', 'add x0, x1, x2', 'bl 0x2000'])
        assert not constants(d)
        d = run('constant-pair-load-clobber', ['mov x0, #1', 'mov x1, #2', 'ldp x0, x1, [x2]', 'bl 0x2000'])
        assert not constants(d)
        d = run('constant-call-barrier', ['mov x0, #1', 'bl 0x2000', 'bl 0x2000'])
        assert constants(d, 0) == {'x0': 1} and not constants(d, 1)
        d = run('constant-join-barrier', ['mov x0, #1', 'cbz x1, 0x1008', 'bl 0x2000'])
        assert not constants(d)
        d = run('constant-incoming-entry', ['mov x0, #1', 'bl 0x2000'], {0x3000: ['b 0x1004']})
        assert not constants(d)
        d = run('constant-no-cross-payload', ['mov x0, #1'], {0x2000: ['bl 0x3000'], 0x3000: ['ret']})
        assert not constants(d)
        d = run('constant-bounded-proof', ['mov x0, #1'] + ['mov x0, x0'] * 64 + ['bl 0x2000'])
        assert not constants(d)
        d = run('tail-jump-not-call-inputs', ['mov x0, #1', 'b 0x2000'])
        assert not constants(d)
        d = run('dispatch-negative-index-and-bias', ['mov x0, #1', 'sub x30, x0, #5', 'ldr x30, [x21, x30, lsl #3]', 'blr x30'])
        access = d['edges'][0]['dispatch']
        assert (access['index'], access['table_index'], access['resolution']) == (-4, 0, 'snapshot_entry')
        assert d['edges'][0]['snapshot_target'] == 0x2000 and access['proof'] == [0x1000, 0x1004]
        d = run('dispatch-derived-base-and-index-copy', ['mov x0, #1', 'add x16, x21, #8', 'mov x17, x0', 'ldr x30, [x16, x17, lsl #3]', 'mov x2, x30', 'blr x2'])
        assert d['edges'][0]['snapshot_target'] == 0x2000 and d['edges'][0]['dispatch']['table_index'] == 6
        for name, value, expected in [('dispatch-low-bound', -5, 'out_of_bounds'), ('dispatch-high-bound', 4, 'out_of_bounds'), ('dispatch-unmapped-entry', -2, 'unmapped_entry'), ('dispatch-null-error', -1, 'null_error_entry')]:
            d = run(name, [f'mov x0, #{value}', 'ldr x30, [x21, x0, lsl #3]', 'blr x30'])
            assert d['edges'][0]['dispatch']['resolution'] == expected
            assert d['edges'][0]['snapshot_target'] == (0x3000 if value == -1 else None)
        d = run('dispatch-signed-overflow', ['mov x0, #0x7fffffffffffffff', 'ldr x30, [x21, x0, lsl #3]', 'blr x30'])
        assert d['edges'][0]['dispatch']['table_index'] is None and d['edges'][0]['snapshot_target'] is None
        d = run('dispatch-misaligned-base', ['mov x0, #0', 'add x16, x21, #1', 'ldr x30, [x16, x0, lsl #3]', 'blr x30'])
        assert d['edges'][0]['dispatch']['resolution'] == 'misaligned_base' and d['edges'][0]['snapshot_target'] is None
        d = run('dispatch-index-captured-at-load', ['mov x0, #0', 'ldr x30, [x21, x0, lsl #3]', 'mov x0, #100', 'blr x30'])
        assert d['edges'][0]['dispatch']['index'] == 0 and d['edges'][0]['dispatch']['table_index'] == 4
        d = run('dispatch-index-cross-call-unknown', ['mov x0, #0', 'bl 0x2000', 'ldr x30, [x21, x0, lsl #3]', 'blr x30'])
        assert d['edges'][-1]['dispatch']['index'] is None and d['edges'][-1]['snapshot_target'] is None
        d = run('bitfield-index-expression', ['ubfx x0, x1, #12, #20', 'mov x17, #0x1000', 'sub x30, x0, x17', 'ldr x30, [x21, x30, lsl #3]', 'blr x30'])
        expression = d['edges'][0]['dispatch']['expression']
        assert (expression['site'], expression['source_register'], expression['lsb'], expression['width'], expression['addend']) == (0x1000, 'x1', 12, 20, -4096)
        assert expression['proof'] == [0x1000, 0x1004, 0x1008] and d['edges'][0]['snapshot_target'] is None
        d = run('copied-expression-and-shifted-offset', ['ubfx x0, x1, #12, #20', 'mov x2, x0', 'add x30, x2, #2, lsl #12', 'ldr x30, [x21, x30, lsl #3]', 'blr x30'])
        assert d['edges'][0]['dispatch']['expression']['addend'] == 8192
        d = run('expression-narrow-write-kills', ['ubfx x0, x1, #12, #20', 'mov w0, w2', 'ldr x30, [x21, x0, lsl #3]', 'blr x30'])
        assert d['edges'][0]['dispatch']['expression'] is None
        d = run('expression-cross-join-kills', ['ubfx x0, x1, #12, #20', 'cbz x2, 0x1008', 'ldr x30, [x21, x0, lsl #3]', 'blr x30'])
        assert d['edges'][0]['dispatch']['expression'] is None
        d = run('expression-offset-overflow-kills', ['ubfx x0, x1, #12, #20', 'mov x17, #0x7fffffffffffffff', 'add x30, x0, x17', 'ldr x30, [x21, x30, lsl #3]', 'blr x30'])
        assert d['edges'][0]['dispatch']['expression'] is None
        d = run('constant-register-arithmetic-wraps', ['mov w0, #-1', 'add w0, w0, #1', 'mov x1, #-1', 'add x1, x1, #1', 'mov x2, #4', 'sub x3, x2, x0', 'bl 0x2000'])
        assert constants(d) == {'x0': 0, 'x1': 0, 'x2': 4, 'x3': 4}
        d = run('constant-extracted-index', ['mov x0, #0x1000', 'ubfx x0, x0, #12, #20', 'ldr x30, [x21, x0, lsl #3]', 'blr x30'])
        assert d['edges'][0]['snapshot_target'] == 0x2004 and d['edges'][0]['dispatch']['expression'] is None
        def resolved(data):
            return [e['static_dispatch'] for e in data['edges'] if e['static_dispatch'] is not None]

        d = run('receiver-pool-object', ['ldr x1, [x27, #40]', 'ldur x0, [x1, #-1]', 'ubfx x0, x0, #8, #16', 'ldr x30, [x21, x0, lsl #3]', 'blr x30'])
        assert resolved(d)[0]['index'] == 1 and resolved(d)[0]['snapshot_target'] == 0x2004
        d = run('receiver-allocation-result', ['bl 0x2000', 'mov x1, x0', 'ldur w2, [x1, #-1]', 'ubfx w2, w2, #8, #16', 'ldr x30, [x21, x2, lsl #3]', 'blr x30'])
        assert resolved(d)[0]['snapshot_target'] == 0x2004
        d = run('receiver-null-register', ['ldur x0, [x22, #-1]', 'ubfx x0, x0, #8, #16', 'ldr x30, [x21, x0, lsl #3]', 'blr x30'])
        assert resolved(d)[0]['index'] == 1
        d = run('receiver-equal-cid-join', ['cbz x0, 0x100c', 'ldr x1, [x27, #40]', 'b 0x1010', 'ldr x1, [x27, #48]', 'ldur x0, [x1, #-1]', 'ubfx x0, x0, #8, #16', 'ldr x30, [x21, x0, lsl #3]', 'blr x30'])
        assert resolved(d)[0]['index'] == 1
        d = run('receiver-conflicting-cid-join', ['cbz x0, 0x100c', 'ldr x1, [x27, #40]', 'b 0x1010', 'ldr x1, [x27, #56]', 'ldur x0, [x1, #-1]', 'ubfx x0, x0, #8, #16', 'ldr x30, [x21, x0, lsl #3]', 'blr x30'])
        assert not resolved(d)
        d = run('receiver-unknown-predecessor', ['cbz x0, 0x100c', 'ldr x1, [x27, #40]', 'b 0x1010', 'nop', 'ldur x0, [x1, #-1]', 'ubfx x0, x0, #8, #16', 'ldr x30, [x21, x0, lsl #3]', 'blr x30'])
        assert not resolved(d)
        d = run('receiver-branch-guard-fallthrough', ['ubfx x0, x1, #8, #16', 'cmp w0, #1', 'b.ne 0x1014', 'ldr x30, [x21, x0, lsl #3]', 'blr x30', 'ret'])
        assert resolved(d)[0]['index'] == 1
        d = run('receiver-branch-guard-target', ['ubfx x0, x1, #8, #16', 'cmp w0, #1', 'b.eq 0x1010', 'ret', 'ldr x30, [x21, x0, lsl #3]', 'blr x30'])
        assert resolved(d)[0]['index'] == 1
        d = run('receiver-w-guard-keeps-unknown-upper-bits', ['cmp w0, #1', 'b.ne 0x1010', 'ldr x30, [x21, x0, lsl #3]', 'blr x30', 'ret'])
        assert not resolved(d)
        d = run('receiver-flags-clobber', ['ubfx x0, x1, #8, #16', 'cmp w0, #1', 'cmp x2, x3', 'b.ne 0x1018', 'ldr x30, [x21, x0, lsl #3]', 'blr x30', 'ret'])
        assert not resolved(d)
        d = run('receiver-compared-register-clobber', ['ubfx x0, x1, #8, #16', 'cmp w0, #1', 'mov x0, x2', 'b.ne 0x1018', 'ldr x30, [x21, x0, lsl #3]', 'blr x30', 'ret'])
        assert not resolved(d)
        d = run('receiver-external-entry-invalidates-guard', ['ubfx x0, x1, #8, #16', 'cmp w0, #1', 'b.ne 0x1014', 'ldr x30, [x21, x0, lsl #3]', 'blr x30', 'ret'], {0x3000: ['b 0x100c']})
        assert not resolved(d)
        d = run('receiver-unknown-call-clobber', ['ldr x1, [x27, #40]', 'blr x2', 'ldur x0, [x1, #-1]', 'ubfx x0, x0, #8, #16', 'ldr x30, [x21, x0, lsl #3]', 'blr x30'])
        assert not resolved(d)
        d = run('receiver-header-write-clobber', ['ldr x1, [x27, #40]', 'stur x2, [x1, #-1]', 'ldur x0, [x1, #-1]', 'ubfx x0, x0, #8, #16', 'ldr x30, [x21, x0, lsl #3]', 'blr x30'])
        assert not resolved(d)
        d = run('receiver-field-store-preserves-class', ['bl 0x2000', 'stur x2, [x0, #7]', 'ldur x0, [x0, #-1]', 'ubfx x0, x0, #8, #16', 'ldr x30, [x21, x0, lsl #3]', 'blr x30'])
        assert resolved(d)[0]['index'] == 1
        d = run('receiver-unknown-store-clobber', ['ldr x1, [x27, #40]', 'str x2, [x3]', 'ldur x0, [x1, #-1]', 'ubfx x0, x0, #8, #16', 'ldr x30, [x21, x0, lsl #3]', 'blr x30'])
        assert not resolved(d)
        d = run('receiver-loop-stable-class', ['ldr x1, [x27, #40]', 'ldur x0, [x1, #-1]', 'ubfx x0, x0, #8, #16', 'cbnz x2, 0x1004', 'ldr x30, [x21, x0, lsl #3]', 'blr x30'])
        assert resolved(d)[0]['index'] == 1
        d = run('receiver-loop-changing-class', ['ldr x1, [x27, #40]', 'ldur x0, [x1, #-1]', 'ubfx x0, x0, #8, #16', 'ldr x1, [x27, #56]', 'cbnz x2, 0x1004', 'ldr x30, [x21, x0, lsl #3]', 'blr x30'])
        assert not resolved(d)
        d = run('receiver-unknown-indirect-jump-disables-cfg', ['ldr x1, [x27, #40]', 'ldur x0, [x1, #-1]', 'ubfx x0, x0, #8, #16', 'ldr x30, [x21, x0, lsl #3]', 'blr x30', 'br x2'])
        assert not resolved(d)
        d = run('receiver-heap-tag-test-through-w-register', ['ldr x1, [x27, #40]', 'mov x0, #2', 'tbz w1, #0, 0x1014', 'ldur x0, [x1, #-1]', 'ubfx x0, x0, #8, #16', 'ldr x30, [x21, x0, lsl #3]', 'blr x30'])
        assert resolved(d)[0]['index'] == 1
        d = run('receiver-trap-stops-flow', ['brk #0', 'mov x0, #1', 'ldr x30, [x21, x0, lsl #3]', 'blr x30'])
        assert not resolved(d)
        d = run('receiver-proof-limit', ['ldr x1, [x27, #40]'] + ['mov x1, x1'] * 129 + ['ldur x0, [x1, #-1]', 'ubfx x0, x0, #8, #16', 'ldr x30, [x21, x0, lsl #3]', 'blr x30'])
        assert not resolved(d)
        d = run('receiver-instruction-limit', ['mov x0, #1', 'ldr x30, [x21, x0, lsl #3]', 'blr x30'],
                extra={0x2000: None, 0x20000: ['ret']}, suffix=bytes.fromhex('1f2003d5') * 16382)
        assert not resolved(d)
        d = run('receiver-frame-register-repurposed-as-heap', ['ldr x1, [x27, #40]', 'mov x29, x1', 'stur x2, [x29, #-1]', 'ldur x0, [x1, #-1]', 'ubfx x0, x0, #8, #16', 'ldr x30, [x21, x0, lsl #3]', 'blr x30'])
        assert not resolved(d)
        d = run('receiver-stack-prologue-and-aliased-store', ['stp x29, x30, [x15, #-16]!', 'mov x29, x15', 'sub x15, x15, #32', 'ldr x1, [x27, #40]', 'mov x16, x29', 'stur x1, [x16, #-8]', 'ldur x0, [x1, #-1]', 'ubfx x0, x0, #8, #16', 'ldr x30, [x21, x0, lsl #3]', 'blr x30'])
        assert resolved(d)[0]['index'] == 1
        d = run('receiver-msr-flags-invalidates-compare', ['ubfx x0, x1, #8, #16', 'cmp w0, #1', 'msr nzcv, x2', 'b.ne 0x1018', 'ldr x30, [x21, x0, lsl #3]', 'blr x30', 'ret'])
        assert not resolved(d)
        d = run('receiver-system-call-invalidates-values', ['mov x0, #1', 'svc #0', 'ldr x30, [x21, x0, lsl #3]', 'blr x30'])
        assert not resolved(d)
        invalid = [str(executable), str(temp / 'invalid.json'), '0x1000', str(temp / '4096.bin'), '0x1000', str(temp / '4096.bin')]
        if args.memcheck:
            invalid = ['valgrind', '--quiet', '--error-exitcode=97', '--leak-check=full',
                       '--errors-for-leak-kinds=definite,indirect,possible'] + invalid
        failed = subprocess.run(invalid, capture_output=True, text=True, env=dict(os.environ,
            ASAN_OPTIONS=f'halt_on_error=1:detect_leaks={1 if sys.platform.startswith("linux") else 0}', UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1'))
        assert failed.returncode == 1 and 'Overlapping or unsorted' in failed.stderr and 'ERROR:' not in failed.stderr, failed.stderr
        passed.append('overlapping-ranges-cleanup')
        print(json.dumps({'status': 'PASSED', 'sanitizers': [] if args.memcheck else ['address', 'undefined'],
                          'memcheck': args.memcheck,
                          'cases': passed, 'case_count': len(passed)}, indent=2))


if __name__ == '__main__':
    main()
