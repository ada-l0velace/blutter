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
                        str(root / 'blutter/src/CallEffects.cpp'),
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
                            {'pool_heap_classes': [[3, 1], [4, 1], [5, 2]], 'class_allocations': [[0x2000, 1]],
                             'pool_code_entries': [[2, 7, 0x2000], [2, 15, 0x2004], [6, 7, 0x5000], [7, 7, 0xa000], [8, 7, 0xc000]],
                             'leaf_math_contract': [0x80, 0x88, 0x90, 8],
                             'allocation_body_bounds': [[0x2000, 7, 31], [0x7000, 7, 15], [0x8000, 7, 39]],
                             'array_body_contract': [0x6000, 2, 15, 4, 1],
                             'thread_heap_classes': [[0xa8, 2]],
                             'predefined_allocations': [[0x6000, 2], [0x7000, 3], [0x8000, 4]],
                             'preserved_call_registers': [[0x7000, 1 << 2], [0x9000, 31]],
                             'nonreturning_calls': [[0xc000, 'range_error_without_fpu']],
                             'frame_preserving_calls': [[0x3000, 'stack_overflow_without_fpu'], [0x9000, 'array_write_barrier'], [0xa000, 'double_to_integer']]})
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
        for name, value, expected in [('dispatch-low-bound', -5, 'out_of_bounds'), ('dispatch-high-bound', 5, 'out_of_bounds'), ('dispatch-unmapped-entry', -2, 'unmapped_entry'), ('dispatch-null-error', -1, 'null_error_entry')]:
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

        def inputs(data, edge=0):
            return {v['sp_offset']: (v['kind'], int(v['value'], 16)) for v in data['edges'][edge]['stack_inputs']}

        pair = ['ldr x0, [x26, #0xa8]', 'ldr x1, [x27, #40]', 'stp x0, x1, [x15]']
        d = run('stack-typed-thread-and-pool-pair', pair + ['bl 0x2000'])
        assert inputs(d) == {0: ('heap_class', 2), 8: ('heap_class', 1)}
        assert d['edges'][0]['stack_inputs'][0]['proof'] == [0x1000, 0x1008]
        d = run('stack-single-word-and-class', ['mov w0, #-1', 'str x0, [x15]', 'ldr x1, [x27, #40]', 'str x1, [x15, #16]', 'bl 0x2000'])
        assert inputs(d) == {0: ('word', 0xffffffff), 16: ('heap_class', 1)}
        d = run('stack-unknown-thread-field-is-not-object', ['ldr x0, [x26, #0x78]', 'str x0, [x15]', 'bl 0x2000'])
        assert not inputs(d)
        d = run('stack-derived-thread-root', ['add x16, x26, #0xa0', 'ldr x0, [x16, #8]', 'str x0, [x15]', 'bl 0x2000'])
        assert inputs(d) == {0: ('heap_class', 2)}
        d = run('stack-certificate-ubfm-lsr-alias-is-not-ubfx', ['mov x0, #1', 'lsr x2, x3, #8', 'str x0, [x15]', 'bl 0x2000'])
        assert inputs(d) == {0: ('word', 1)}
        d = run('stack-written-thread-root-disables-typed-load', ['ldr x0, [x26, #0xa8]', 'str x0, [x15]', 'mov x26, x1', 'bl 0x2000'])
        assert not inputs(d)
        d = run('stack-stored-value-survives-register-clobber', pair + ['mov x0, #7', 'mov x1, x2', 'bl 0x2000'])
        assert inputs(d) == {0: ('heap_class', 2), 8: ('heap_class', 1)}
        d = run('stack-overwrite-latest-known-value', pair + ['mov x2, #7', 'str x2, [x15]', 'bl 0x2000'])
        assert inputs(d) == {0: ('word', 7), 8: ('heap_class', 1)}
        d = run('stack-overwrite-unknown-removes-one-slot', pair + ['str x2, [x15]', 'bl 0x2000'])
        assert inputs(d) == {8: ('heap_class', 1)}
        for name, clobber in [
            ('narrow-overlap', ['str w2, [x15, #4]']),
            ('byte-overlap', ['strb w2, [x15, #7]']),
            ('indexed-stack-store', ['str x2, [x15, x3]']),
            ('unknown-memory-store', ['str x2, [x3]']),
            ('object-header-store', ['stur x2, [x1, #-1]']),
            ('unaligned-stack-store', ['stur x2, [x15, #1]']),
            ('preindex-stack-store', ['str x2, [x15, #-16]!']),
            ('postindex-stack-store', ['str x2, [x15], #16']),
            ('narrow-pair-stack-store', ['stp w2, w3, [x15]']),
            ('simd-stack-store', ['str q0, [x15]']),
            ('caller-fp-may-alias', ['str x2, [x29]']),
            ('interrupt-barrier', ['svc #0']),
            ('branch-boundary', ['b 0x1010']),
            ('unknown-sp', ['mov x15, x3']),
            ('cache-line-zero-is-a-memory-write', ['dc zva, x15']),
        ]:
            d = run('stack-' + name, pair + clobber + ['bl 0x2000'])
            assert not inputs(d), (name, inputs(d))
        d = run('stack-known-heap-field-preserves-values', pair + ['stur x2, [x1, #7]', 'bl 0x2000'])
        assert inputs(d) == {0: ('heap_class', 2), 8: ('heap_class', 1)}
        d = run('stack-call-barrier', pair + ['bl 0x2000', 'bl 0x2000'])
        assert inputs(d) and not inputs(d, 1)
        d = run('stack-frame-alias-and-offset', ['stp x29, x30, [x15, #-16]!', 'mov x29, x15', 'sub x15, x15, #32', 'mov x0, #5', 'stur x0, [x29, #-32]', 'bl 0x2000'])
        assert inputs(d) == {0: ('word', 5)}
        d = run('stack-moved-sp-relative-observations', pair + ['sub x15, x15, #16', 'bl 0x2000'])
        assert inputs(d) == {16: ('heap_class', 2), 24: ('heap_class', 1)}
        d = run('stack-bounded-window-and-zero-register', ['str xzr, [x15, #248]', 'str xzr, [x15, #256]', 'bl 0x2000'])
        assert inputs(d) == {248: ('word', 0)}

        def loads(data):
            return [(v['site'], v['entry_sp_offset'], v['register'], v['width']) for v in data['entry_stack_loads']]

        prologue = ['stp x29, x30, [x15, #-16]!', 'mov x29, x15', 'sub x15, x15, #32']
        d = run('entry-stack-loads-after-call-keep-frame-coordinates', prologue + ['bl 0x2000', 'ldr x2, [x29, #16]', 'ldr w3, [x29, #24]'])
        assert loads(d) == [(0x1010, 0, 'x2', 8), (0x1014, 8, 'w3', 4)]
        d = run('entry-stack-pair-loads', prologue + ['ldp x0, x1, [x29, #16]'])
        assert loads(d) == [(0x100c, 0, 'x0', 8), (0x100c, 8, 'x1', 8)]
        d = run('entry-stack-caller-fp-is-unrelated', ['ldr x0, [x29, #16]'])
        assert not loads(d)
        d = run('entry-stack-interior-entry-loses-payload-anchor', prologue + ['ldr x0, [x29, #16]'], {0x3000: ['b 0x100c']})
        assert not loads(d)
        d = run('entry-stack-unknown-fp-not-resurrected-by-call', ['mov x29, x2', 'bl 0x2000', 'ldr x0, [x29, #16]'])
        assert not loads(d)
        d = run('entry-stack-unknown-sp-not-resurrected-by-call', ['mov x15, x2', 'bl 0x2000', 'ldr x0, [x15]'])
        assert not loads(d)
        d = run('entry-stack-interrupt-does-not-reset-frame', prologue + ['svc #0', 'ldr x0, [x29, #16]'])
        assert not loads(d)
        d = run('receiver-typed-thread-singleton', ['ldr x1, [x26, #0xa8]', 'ldur x0, [x1, #-1]', 'ubfx x0, x0, #8, #16', 'ldr x30, [x21, x0, lsl #3]', 'blr x30'])
        assert resolved(d)[0]['index'] == 2

        caller = ['ldr x0, [x26, #0xa8]', 'str x0, [x15]', 'bl 0x4000']
        dispatch = ['ldur x0, [x2, #-1]', 'ubfx x0, x0, #8, #16', 'ldr x30, [x21, x0, lsl #3]', 'blr x30', 'ret']
        def contexts(data):
            return [v for v in data['call_contexts'] if v['payload'] == 0x4000]

        d = run('context-input-receiver-class', caller, {0x4000: prologue + ['ldr x2, [x29, #16]'] + dispatch})
        assert len(contexts(d)) == 1 and contexts(d)[0]['resolutions'][0]['index'] == 2
        assert not resolved(d)  # A caller context is not a global receiver type.
        d = run('context-same-bindings-share-analysis', caller + caller, {0x4000: prologue + ['ldr x2, [x29, #16]'] + dispatch})
        assert len(contexts(d)) == 1 and contexts(d)[0]['callers'] == [0x1008, 0x1014]
        d = run('context-different-callers-keep-different-classes', caller + ['ldr x0, [x27, #40]', 'str x0, [x15]', 'bl 0x4000'],
                {0x4000: prologue + ['ldr x2, [x29, #16]'] + dispatch})
        assert {v['resolutions'][0]['index'] for v in contexts(d)} == {1, 2}
        assert all(len(v['callers']) == 1 for v in contexts(d))
        d = run('context-unknown-caller-not-credited', caller + ['str x2, [x15]', 'bl 0x4000'],
                {0x4000: prologue + ['ldr x2, [x29, #16]'] + dispatch})
        assert len(contexts(d)) == 1 and contexts(d)[0]['callers'] == [0x1008]
        d = run('context-allocation-contract-preserves-input', caller,
                {0x4000: prologue + ['bl 0x2000', 'ldr x2, [x29, #16]'] + dispatch})
        assert contexts(d)[0]['resolutions'][0]['index'] == 2
        d = run('context-stack-check-contract-preserves-join', caller,
                {0x4000: prologue + ['cbz x7, 0x4014', 'bl 0x3000', 'ldr x2, [x29, #16]'] + dispatch})
        assert contexts(d)[0]['resolutions'][0]['index'] == 2
        d = run('context-other-interior-entry-is-not-this-invocation', caller,
                {0x4000: prologue + ['ldr x2, [x29, #16]'] + dispatch, 0x5000: ['b 0x400c']})
        assert contexts(d)[0]['resolutions'][0]['index'] == 2
        d = run('context-negative-local-store-preserves-input', caller,
                {0x4000: prologue + ['stur xzr, [x29, #-8]', 'ldr x2, [x29, #16]'] + dispatch})
        assert contexts(d)[0]['resolutions'][0]['index'] == 2
        for name, middle in [
            ('full-input-overwrite', ['str xzr, [x29, #16]']),
            ('partial-input-overwrite', ['str w0, [x29, #20]']),
            ('byte-input-overwrite', ['strb w0, [x29, #23]']),
            ('pair-input-overlap', ['stp x0, x1, [x29, #8]']),
            ('unknown-write-alias', ['str x0, [x3]']),
            ('atomic-release-write', ['add x3, x29, #16', 'stlr x0, [x3]']),
            ('exclusive-write', ['add x3, x29, #16', 'stxr w7, x0, [x3]']),
            ('cache-zero-write', ['add x3, x29, #16', 'dc zva, x3']),
            ('indexed-write-alias', ['str x0, [x29, x7]']),
            ('unknown-call', ['bl 0x5000']),
            ('indirect-call', ['blr x7']),
            ('recursive-call', ['bl 0x4000']),
            ('unknown-call-never-reseeded', ['bl 0x5000', 'bl 0x2000']),
            ('input-write-never-reseeded', ['str xzr, [x29, #16]', 'bl 0x2000']),
            ('stack-address-call-alias', ['add x1, x29, #16', 'bl 0x2000']),
            ('interrupt-kills-inputs', ['svc #0']),
            ('join-must-preserve-input-on-both-paths', ['cbz x7, 0x4014', 'str xzr, [x29, #16]']),
        ]:
            d = run('context-' + name, caller, {0x4000: prologue + middle + ['ldr x2, [x29, #16]'] + dispatch})
            assert not contexts(d), (name, contexts(d))
        d = run('context-unowned-frame-call-kills-input', caller,
                {0x4000: ['bl 0x2000', 'ldr x2, [x15]'] + dispatch})
        assert not contexts(d)
        d = run('context-narrow-pointer-load-does-not-keep-class', caller,
                {0x4000: prologue + ['ldr w2, [x29, #16]'] + dispatch})
        assert not contexts(d)
        d = run('context-word-input-and-narrow-zero-extension', ['movz x0, #1, lsl #32', 'movk x0, #2', 'str x0, [x15]', 'bl 0x4000'],
                {0x4000: prologue + ['ldr w0, [x29, #16]', 'ldr x30, [x21, x0, lsl #3]', 'blr x30', 'ret']})
        assert contexts(d)[0]['resolutions'][0]['index'] == 2

        d = run('predefined-allocation-return-class', ['bl 0x6000', 'mov x2, x0'] + dispatch)
        assert resolved(d)[0]['index'] == 2
        d = run('predefined-array-filled-and-passed', ['bl 0x6000', 'stur wzr, [x0, #15]', 'str x0, [x15]', 'bl 0x4000'],
                {0x4000: prologue + ['ldr x2, [x29, #16]'] + dispatch})
        assert contexts(d)[0]['resolutions'][0]['index'] == 2
        for name, between in [('wrong-interior-entry', ['bl 0x6004']),
                              ('unknown-call-clobbers-return', ['bl 0x6000', 'bl 0x5000']),
                              ('narrowed-return-is-not-a-pointer', ['bl 0x6000', 'mov w0, w0'])]:
            d = run('predefined-' + name, between + ['mov x2, x0'] + dispatch)
            assert not resolved(d)

        spill = prologue + ['ldr x0, [x27, #40]', 'stur x0, [x29, #-8]']
        d = run('spill-class-reload-after-register-clobber', spill + ['mov x0, x3', 'ldur x2, [x29, #-8]'] + dispatch)
        assert resolved(d)[0]['index'] == 1
        d = run('spill-class-keeps-store-and-load-proof', spill + ['b 0x1018', 'ldur x2, [x29, #-8]'] + dispatch)
        assert {0x100c, 0x1010, 0x1018} <= set(resolved(d)[0]['proof'])
        d = run('spill-preserved-by-known-user-allocation', spill + ['bl 0x2000', 'ldur x2, [x29, #-8]'] + dispatch)
        assert resolved(d)[0]['index'] == 1
        d = run('spill-predefined-array-survives-known-allocation', prologue + ['bl 0x6000', 'stur x0, [x29, #-8]', 'bl 0x2000',
                     'ldur x0, [x29, #-8]', 'str x0, [x15]', 'bl 0x4000'],
                {0x4000: prologue + ['ldr x2, [x29, #16]'] + dispatch})
        assert contexts(d)[0]['resolutions'][0]['index'] == 2
        d = run('spill-known-overwrite-replaces-class', spill + ['ldr x0, [x27, #56]', 'stur x0, [x29, #-8]', 'ldur x2, [x29, #-8]'] + dispatch)
        assert resolved(d)[0]['index'] == 2
        d = run('spill-frame-alias', prologue + ['ldr x0, [x27, #40]', 'mov x16, x29', 'stur x0, [x16, #-8]',
                     'ldur x2, [x29, #-8]'] + dispatch)
        assert resolved(d)[0]['index'] == 1
        for name, middle in [
            ('unknown-overwrite', ['stur x3, [x29, #-8]']),
            ('narrow-overlap', ['stur w3, [x29, #-4]']),
            ('narrow-pointer-store', ['stur w0, [x29, #-8]']),
            ('unknown-memory-write', ['str x3, [x4]']),
            ('atomic-memory-write', ['stlr x3, [x29]']),
            ('cache-memory-write', ['dc zva, x29']),
            ('unknown-call', ['bl 0x5000']),
            ('no-reseed-after-unknown-call', ['bl 0x5000', 'bl 0x2000']),
            ('input-frame-address-escapes-in-register', ['mov x1, x29', 'bl 0x2000']),
            ('deallocated-frame-does-not-resurrect', ['mov x15, x29', 'sub x15, x15, #32']),
            ('system-interrupt', ['svc #0']),
        ]:
            d = run('spill-' + name, spill + middle + ['ldur x2, [x29, #-8]'] + dispatch)
            assert not resolved(d), (name, resolved(d))
        d = run('spill-narrow-load-does-not-keep-class', spill + ['ldur w2, [x29, #-8]'] + dispatch)
        assert not resolved(d)
        d = run('spill-unknown-entry-cannot-invent-frame', ['ldr x0, [x27, #40]', 'stur x0, [x29, #-8]',
                     'ldur x2, [x29, #-8]'] + dispatch)
        assert not resolved(d)
        d = run('spill-conflicting-class-join', spill + ['cbz x7, 0x1020', 'ldr x0, [x27, #56]', 'stur x0, [x29, #-8]',
                     'ldur x2, [x29, #-8]'] + dispatch)
        assert not resolved(d)
        d = run('spill-unknown-interior-entry-is-not-initialized', spill + ['ldur x2, [x29, #-8]'] + dispatch,
                {0x5000: ['b 0x1014']})
        assert not resolved(d)
        d = run('spill-proof-bound', spill + ['bl 0x2000'] * 130 + ['ldur x2, [x29, #-8]'] + dispatch)
        assert not resolved(d)
        d = run('helper-preserves-only-declared-register', ['ldr x2, [x27, #56]', 'bl 0x7000'] + dispatch)
        assert resolved(d)[0]['index'] == 2 and 0x1004 in resolved(d)[0]['proof']
        d = run('helper-clobbers-undeclared-register', ['ldr x1, [x27, #56]', 'bl 0x7000', 'mov x2, x1'] + dispatch)
        assert not resolved(d)
        d = run('helper-result-overwrites-old-return-class', ['ldr x0, [x27, #56]', 'bl 0x7000', 'mov x2, x0'] + dispatch)
        assert resolved(d)[0]['index'] == 3
        d = run('helper-w-register-unknown-upper-bits-remain-unknown', ['cmp w2, #2', 'bl 0x7000',
                     'ldr x30, [x21, x2, lsl #3]', 'blr x30'])
        assert not resolved(d)
        d = run('spill-survives-known-closure-allocation', spill + ['bl 0x8000', 'ldur x2, [x29, #-8]'] + dispatch)
        assert resolved(d)[0]['index'] == 1
        d = run('spill-slot-bound', ['stp x29, x30, [x15, #-16]!', 'mov x29, x15', 'sub x15, x15, #528',
                     'ldr x0, [x27, #40]'] + [f'stur x0, [x29, #-{8+i*8}]' if 8+i*8 <= 256 else
                         f'str x0, [x15, #{528-8-i*8}]' for i in range(65)] + ['ldur x2, [x29, #-8]'] + dispatch)
        assert not resolved(d)

        derived = prologue + ['bl 0x6000', 'mov x1, x0', 'stur x0, [x29, #-8]', 'add x25, x1, #15', 'str wzr, [x25]']
        d = run('heap-address-store-preserves-frame-and-class', derived + ['ldur x2, [x29, #-8]'] + dispatch)
        assert resolved(d)[0]['index'] == 2
        d = run('array-barrier-preserves-register-and-spill-class', derived + ['bl 0x9000', 'ldur x2, [x29, #-8]'] + dispatch)
        assert resolved(d)[0]['index'] == 2
        d = run('array-barrier-conditional-path-join', derived + ['cbz x7, 0x1028', 'bl 0x9000', 'ldur x2, [x29, #-8]'] + dispatch)
        assert resolved(d)[0]['index'] == 2
        d = run('heap-address-can-return-to-object-base', ['ldr x1, [x27, #40]', 'add x3, x1, #24', 'sub x2, x3, #24'] + dispatch)
        assert resolved(d)[0]['index'] == 1
        d = run('heap-address-signed-delta-and-copy', ['ldr x1, [x27, #40]', 'add x3, x1, #24', 'mov x4, #-24',
                     'mov x5, x3', 'add x2, x5, x4'] + dispatch)
        assert resolved(d)[0]['index'] == 1
        for name, middle in [
            ('derived-header-write', ['sub x25, x1, #1', 'str xzr, [x25]']),
            ('effective-displacement-reaches-header', ['add x25, x1, #15', 'stur xzr, [x25, #-16]']),
            ('narrowed-address', ['mov w25, w25', 'str wzr, [x25]']),
            ('unknown-indexed-store', ['str wzr, [x25, x7]']),
            ('unknown-call-still-kills', ['bl 0x5000']),
            ('slot-register-clobbered-by-barrier', ['bl 0x9000', 'str wzr, [x25]']),
        ]:
            d = run('heap-address-' + name, derived + middle + ['ldur x2, [x29, #-8]'] + dispatch)
            assert not resolved(d), (name, resolved(d))
        d = run('heap-address-not-preserved-through-allocating-gc', ['ldr x1, [x27, #40]', 'add x2, x1, #8',
                     'bl 0x7000', 'sub x2, x2, #8'] + dispatch)
        assert not resolved(d)
        d = run('heap-address-clobbered-by-system-memory-operation', derived + ['dc zva, x25', 'ldur x2, [x29, #-8]'] + dispatch)
        assert not resolved(d)
        d = run('heap-address-proof-bound', derived + ['mov x25, x25'] * 129 + ['str wzr, [x25]', 'ldur x2, [x29, #-8]'] + dispatch)
        assert not resolved(d)
        d = run('heap-address-offset-bound', derived + ['add x25, x1, #257, lsl #12', 'str wzr, [x25]', 'ldur x2, [x29, #-8]'] + dispatch)
        assert not resolved(d)
        d = run('heap-address-conflicting-offsets-join', derived + ['cbz x7, 0x102c', 'add x25, x1, #7', 'b 0x1030',
                     'add x25, x1, #15', 'str wzr, [x25]', 'ldur x2, [x29, #-8]'] + dispatch)
        assert not resolved(d)
        d = run('array-barrier-preserves-context-inputs', caller,
                {0x4000: prologue + ['ldr x2, [x29, #16]', 'add x25, x2, #15', 'str wzr, [x25]',
                     'bl 0x9000', 'ldr x2, [x29, #16]'] + dispatch})
        assert contexts(d)[0]['resolutions'][0]['index'] == 2
        epilogue = ['mov x15, x29', 'ldp x29, x30, [x15], #16', 'ret']
        leaf = prologue + ['mov x0, #7', 'str x0, [x15]'] + epilogue
        call_spill = spill + ['bl 0x5000', 'ldur x2, [x29, #-8]'] + dispatch
        d = run('callee-own-frame-preserves-caller-spill', call_spill, {0x5000: leaf})
        assert resolved(d)[0]['index'] == 1 and any(c['payload'] == 0x5000 for c in d['call_effects'])
        d = run('callee-transitive-effects', spill + ['bl 0x4000', 'ldur x2, [x29, #-8]'] + dispatch,
                {0x4000: prologue + ['bl 0x5000'] + epilogue, 0x5000: leaf})
        assert resolved(d)[0]['index'] == 1 and next(c['depth'] for c in d['call_effects'] if c['payload'] == 0x4000) == 2
        d = run('callee-preserves-input-bindings', caller,
                {0x4000: prologue + ['bl 0x5000', 'ldr x2, [x29, #16]'] + dispatch, 0x5000: leaf})
        assert contexts(d)[0]['resolutions'][0]['index'] == 2
        d = run('callee-known-pool-code-target', spill + ['bl 0x4000', 'ldur x2, [x29, #-8]'] + dispatch,
                {0x4000: prologue + ['ldr x30, [x27, #64]', 'ldur x30, [x30, #7]', 'blr x30'] + epilogue, 0x5000: leaf})
        assert resolved(d)[0]['index'] == 1
        math = ['stp x29, x30, [x15, #-16]!', 'mov x29, x15', 'and x15, x15, #0xfffffffffffffff0',
                'mov sp, x15', 'ldr x16, [x26, #0x80]', 'str x16, [x26, #0x88]', 'blr x16',
                'mov x16, #8', 'str x16, [x26, #0x88]', 'ldr x16, [x26, #0x90]',
                'sub sp, x16, #1, lsl #12', 'mov x15, x29', 'ldp x29, x30, [x15], #16']
        d = run('callee-reviewed-unary-math-and-conversion', call_spill,
                {0x5000: prologue + math + ['ldr x30, [x27, #72]', 'ldur x30, [x30, #7]', 'blr x30'] + epilogue})
        assert resolved(d)[0]['index'] == 1
        for name, body in [
            ('unknown-call', prologue + ['bl 0x7004'] + epilogue),
            ('unknown-indirect-call', prologue + ['blr x9'] + epilogue),
            ('recursive-call', prologue + ['bl 0x5000'] + epilogue),
            ('conditional-unknown-call', prologue + ['cbz x0, 0x5014', 'bl 0x7004'] + epilogue),
            ('caller-frame-write', prologue + ['str xzr, [x29, #16]'] + epilogue),
            ('parameter-write', prologue + ['str xzr, [x1, #8]'] + epilogue),
            ('header-write', prologue + ['stur xzr, [x1, #-1]'] + epilogue),
            ('atomic-write', prologue + ['stlr xzr, [x15]'] + epilogue),
            ('system-write', prologue + ['dc zva, x15'] + epilogue),
            ('reserved-register-change', prologue + ['mov x26, x0'] + epilogue),
            ('c-stack-change', prologue + ['mov sp, x0'] + epilogue),
            ('changed-saved-fp', prologue + ['stur xzr, [x29]'] + epilogue),
            ('changed-saved-lr', prologue + ['stur xzr, [x29, #8]'] + epilogue),
            ('unbalanced-return', prologue + ['ret']),
            ('tail-exit', prologue + ['b 0x6004']),
            ('no-return-proof', ['b 0x5000']),
            ('mismatched-frame-join', prologue + ['cbz x0, 0x5014', 'add x15, x15, #8', 'str xzr, [x15]'] + epilogue),
            ('broken-math-field', prologue + math[:4] + ['ldr x16, [x26, #0x98]'] + math[5:] + epilogue),
            ('broken-math-restore', prologue + math[:-1] + ['ldp x29, x30, [x15], #8'] + epilogue),
        ]:
            d = run('callee-rejects-' + name, call_spill, {0x5000: body})
            assert not resolved(d) and not any(c['payload'] == 0x5000 for c in d['call_effects']), name
        d = run('callee-does-not-preserve-working-gprs', spill + ['mov x2, x0', 'bl 0x5000'] + dispatch, {0x5000: leaf})
        assert not resolved(d)
        d = run('callee-caller-stack-alias-still-kills', spill + ['mov x1, x15', 'bl 0x5000', 'ldur x2, [x29, #-8]'] + dispatch, {0x5000: leaf})
        assert not resolved(d)
        d = run('callee-interior-entry-not-summarized', spill + ['bl 0x5004', 'ldur x2, [x29, #-8]'] + dispatch, {0x5000: leaf})
        assert not resolved(d)
        fixed_body = prologue + ['bl 0x2000', 'stur xzr, [x0, #7]'] + epilogue
        d = run('callee-fixed-allocation-body', call_spill, {0x5000: fixed_body})
        assert resolved(d)[0]['index'] == 1 and any(c['payload'] == 0x5000 for c in d['call_effects'])
        array_body = prologue + ['mov x2, #4', 'bl 0x6000', 'stur wzr, [x0, #15]', 'stur wzr, [x0, #19]'] + epilogue
        d = run('callee-exact-array-body', call_spill, {0x5000: array_body})
        assert resolved(d)[0]['index'] == 1
        d = run('callee-derived-array-body-pair', call_spill,
                {0x5000: prologue + ['mov x2, #4', 'bl 0x6000', 'add x3, x0, #23', 'sub x3, x3, #8', 'stp wzr, wzr, [x3]'] + epilogue})
        assert resolved(d)[0]['index'] == 1
        d = run('callee-word-width-copy-and-arithmetic', call_spill,
                {0x5000: prologue + ['mov w3, #8', 'mov w2, w3', 'sub w2, w2, #4', 'bl 0x6000', 'stur wzr, [x0, #19]'] + epilogue})
        assert resolved(d)[0]['index'] == 1
        d = run('callee-array-length-reload', call_spill,
                {0x5000: prologue + ['mov x2, #4', 'stur x2, [x29, #-8]', 'bl 0x2000', 'ldur x2, [x29, #-8]', 'bl 0x6000', 'stur wzr, [x0, #19]'] + epilogue})
        assert resolved(d)[0]['index'] == 1
        d = run('callee-root-heap-reload-across-allocation', call_spill,
                {0x5000: prologue + ['bl 0x2000', 'stur x0, [x29, #-8]', 'bl 0x7000', 'ldur x3, [x29, #-8]', 'stur xzr, [x3, #7]'] + epilogue})
        assert resolved(d)[0]['index'] == 1
        d = run('callee-sdk-preserved-root-heap-register', call_spill,
                {0x5000: prologue + ['bl 0x2000', 'mov x2, x0', 'bl 0x7000', 'stur xzr, [x2, #7]'] + epilogue})
        assert resolved(d)[0]['index'] == 1
        via_dispatch = ['mov x0, #4', 'ldr x30, [x21, x0, lsl #3]', 'blr x30']
        d = run('callee-proven-dispatch-effect-preserves-spill', spill + via_dispatch + ['ldur x2, [x29, #-8]'] + dispatch, {0xb000: leaf})
        assert len(resolved(d)) == 2 and resolved(d)[-1]['index'] == 1
        d = run('callee-proven-dispatch-effect-preserves-inputs', caller,
                {0x4000: prologue + via_dispatch + ['ldr x2, [x29, #16]'] + dispatch, 0xb000: leaf})
        assert contexts(d)[0]['resolutions'][0]['index'] == 2
        d = run('callee-proven-dispatch-without-summary-kills', spill + via_dispatch + ['ldur x2, [x29, #-8]'] + dispatch)
        assert len(resolved(d)) == 1
        d = run('callee-proven-dispatch-unsafe-summary-kills', spill + via_dispatch + ['ldur x2, [x29, #-8]'] + dispatch,
                {0xb000: prologue + ['str xzr, [x1]'] + epilogue})
        assert len(resolved(d)) == 1
        d = run('callee-proven-dispatch-clobbered-target-kills', spill + via_dispatch[:2] + ['mov w30, w30', 'blr x30', 'ldur x2, [x29, #-8]'] + dispatch, {0xb000: leaf})
        assert not resolved(d)
        d = run('callee-proven-dispatch-stack-alias-kills', spill + ['mov x1, x15'] + via_dispatch + ['ldur x2, [x29, #-8]'] + dispatch, {0xb000: leaf})
        assert len(resolved(d)) == 1
        d = run('callee-proven-dispatch-does-not-preserve-gprs', spill + ['mov x2, x0'] + via_dispatch + dispatch, {0xb000: leaf})
        assert len(resolved(d)) == 1
        for name, body in [
            ('header', prologue + ['bl 0x2000', 'stur wzr, [x0, #-1]'] + epilogue),
            ('fixed-object-overrun', prologue + ['bl 0x2000', 'stur xzr, [x0, #31]'] + epilogue),
            ('array-length-field', prologue + ['mov x2, #4', 'bl 0x6000', 'stur wzr, [x0, #11]'] + epilogue),
            ('array-type-argument-field', prologue + ['mov x2, #4', 'bl 0x6000', 'stur wzr, [x0, #7]'] + epilogue),
            ('array-element-overrun', prologue + ['mov x2, #4', 'bl 0x6000', 'stur wzr, [x0, #23]'] + epilogue),
            ('array-wide-overlap', prologue + ['mov x2, #4', 'bl 0x6000', 'stur xzr, [x0, #19]'] + epilogue),
            ('array-pair-overlap', prologue + ['mov x2, #4', 'bl 0x6000', 'add x3, x0, #15', 'stp xzr, xzr, [x3]'] + epilogue),
            ('array-unknown-length', prologue + ['bl 0x6000', 'stur wzr, [x0, #15]'] + epilogue),
            ('array-odd-length', prologue + ['mov x2, #3', 'bl 0x6000', 'stur wzr, [x0, #15]'] + epilogue),
            ('array-negative-length', prologue + ['mov x2, #-2', 'bl 0x6000', 'stur wzr, [x0, #15]'] + epilogue),
            ('array-empty-body', prologue + ['mov x2, #0', 'bl 0x6000', 'stur wzr, [x0, #15]'] + epilogue),
            ('array-bound-budget', prologue + ['movz x2, #32, lsl #16', 'bl 0x6000', 'stur wzr, [x0, #15]'] + epilogue),
            ('indexed-address', prologue + ['bl 0x2000', 'mov x3, #7', 'str xzr, [x0, x3]'] + epilogue),
            ('heap-writeback', prologue + ['bl 0x2000', 'str wzr, [x0, #8]!'] + epilogue),
            ('narrow-pointer', prologue + ['bl 0x2000', 'mov w3, w0', 'stur wzr, [x3, #7]'] + epilogue),
            ('stale-interior-spill', prologue + ['bl 0x2000', 'add x3, x0, #7', 'stur x3, [x29, #-8]', 'bl 0x7000', 'ldur x3, [x29, #-8]', 'str wzr, [x3]'] + epilogue),
            ('stale-interior-register', prologue + ['bl 0x2000', 'add x2, x0, #7', 'bl 0x7000', 'str wzr, [x2]'] + epilogue),
            ('unreviewed-call-after-store', prologue + ['bl 0x2000', 'stur xzr, [x0, #7]', 'bl 0x7004'] + epilogue),
        ]:
            d = run('callee-body-rejects-' + name, call_spill, {0x5000: body})
            assert not resolved(d) and not any(c['payload'] == 0x5000 for c in d['call_effects']), name
        guarded = prologue + ['cbz x0, 0x5020', 'mov x0, #7'] + epilogue + ['bl 0xc000']
        d = run('noreturn-error-tail-allows-returning-effect', call_spill, {0x5000: guarded})
        assert resolved(d)[0]['index'] == 1 and any(c['payload'] == 0x5000 for c in d['call_effects'])
        d = run('noreturn-error-only-frame', call_spill,
                {0x5000: ['cbz x0, 0x5008', 'ret', 'stp x29, x30, [x15, #-16]!', 'mov x29, x15', 'bl 0xc000']})
        assert resolved(d)[0]['index'] == 1
        d = run('noreturn-error-via-audited-pool-code', call_spill,
                {0x5000: guarded[:-1] + ['ldr x30, [x27, #80]', 'ldur x30, [x30, #7]', 'blr x30']})
        assert resolved(d)[0]['index'] == 1
        d = run('noreturn-transitive-returning-effects', spill + ['bl 0x4000', 'ldur x2, [x29, #-8]'] + dispatch,
                {0x4000: prologue + ['bl 0x5000'] + epilogue, 0x5000: guarded})
        assert resolved(d)[0]['index'] == 1 and next(c['depth'] for c in d['call_effects'] if c['payload'] == 0x4000) == 2
        d = run('noreturn-ignores-unreachable-write-after-sink', call_spill,
                {0x5000: guarded + ['str xzr, [x1]', 'ret']})
        assert resolved(d)[0]['index'] == 1
        for name, body in [
            ('neighbor-entry', guarded[:-1] + ['bl 0xc004']),
            ('unreviewed-error-call', guarded[:-1] + ['bl 0x7004']),
            ('unknown-indirect-error-call', guarded[:-1] + ['blr x9']),
            ('only-throwing-is-not-a-returning-summary', prologue + ['bl 0xc000']),
            ('unproved-write-before-error', guarded[:-1] + ['str xzr, [x1]', 'bl 0xc000']),
        ]:
            d = run('noreturn-rejects-' + name, call_spill, {0x5000: body})
            assert not resolved(d) and not any(c['payload'] == 0x5000 for c in d['call_effects']), name
        after_sink = prologue + ['bl 0xc000', 'ldr x2, [x27, #40]'] + dispatch[:-1] + epilogue
        d = run('noreturn-caller-has-no-normal-fallthrough', after_sink)
        assert not resolved(d) and next(n for n in d['nodes'] if n['start'] == 0x1000)['decoded']
        for name, target in [('unknown', 0x7004), ('neighbor', 0xc004)]:
            d = run('noreturn-' + name + '-call-retains-fallthrough', prologue + [f'bl {hex(target)}', 'ldr x2, [x27, #40]'] + dispatch[:-1] + epilogue)
            assert len(resolved(d)) == 1
        d = run('noreturn-ordinary-callee-not-inferred-from-no-ret', prologue + ['bl 0x5000', 'ldr x2, [x27, #40]'] + dispatch[:-1] + epilogue,
                {0x5000: ['brk #0']})
        assert len(resolved(d)) == 1
        d = run('noreturn-external-entry-after-sink-remains-reachable', after_sink, {0x3000: ['b 0x1010']})
        assert len(resolved(d)) == 1
        block = next(b for c in d['receiver_certificates'] if c['payload'] == 0x1000 for b in c['blocks'] if b['start'] == 0x1010)
        assert block['entry'] and block['reachable']
        chain = {0x5000+i*0x100: prologue + [f'bl {hex(0x5100+i*0x100)}'] + epilogue for i in range(8)}
        chain[0x5800] = leaf
        d = run('callee-depth-bound', call_spill, chain)
        assert not resolved(d) and all(c['depth'] <= 8 for c in d['call_effects'])
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
