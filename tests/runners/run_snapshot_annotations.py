#!/usr/bin/env python3
"""Exercise ARM64 provenance safety without a Dart VM (requires C++20, llvm-mc, Capstone)."""
import json
import copy
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
                        str(root / 'blutter/src/RegisterContexts.cpp'),
                        str(root / 'blutter/src/CallResultContexts.cpp'),
                        str(root / 'blutter/src/CallEffects.cpp'),
                        str(root / 'blutter/src/NativeIr.cpp'),
                        str(root / 'blutter/src/Arm64Ir.cpp'),
                        str(root / 'blutter/src/ArrayLengthAnalysis.cpp'),
                        str(root / 'blutter/src/StackCheckAnalysis.cpp'),
                        '-o', str(executable)] + flags, check=True)

        def run(name, assembly, extra=None, suffix=b'', element_bytes=4, late_helper=False, helper_entry_offset=0, native_returns=False):
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
            subprocess.run(command, check=True, env=dict(os.environ, BLUTTER_TEST_ARRAY_BYTES=str(element_bytes), BLUTTER_TEST_LATE_HELPER='1' if late_helper else '0',
                BLUTTER_TEST_HELPER_ENTRY_OFFSET=str(helper_entry_offset),
                BLUTTER_TEST_NATIVE_RETURNS='1' if native_returns else '0',
                ASAN_OPTIONS=f'halt_on_error=1:detect_leaks={leaks}', UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1'))
            result = json.loads((temp / 'out.json').read_text())
            # The checker verifies inductive invariants instead of reproducing the
            # native worklist solver. Its bytes come from the assembler fixtures.
            decoder = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
            decoder.detail = True
            fixture_bytes = {address: (temp / (str(address) + '.bin')).read_bytes() for address in blocks}
            if late_helper:
                fixture_bytes.update({0x10000+n*8: bytes.fromhex('c0035fd6') for n in range(16384)})
            def read(address, length):
                for start, raw in fixture_bytes.items():
                    if start <= address and address+length <= start+len(raw):
                        return raw[address-start:address-start+length]
                raise AssertionError('Read outside authored fixture bytes')
            audit = {'heap_bits_register': 'x28' if element_bytes == 4 else None, 'word_return_register': 'x0', 'pool_heap_classes': [[3, 1], [4, 1], [5, 2]], 'class_allocations': [[0x2000, 1]],
                             'pool_code_entries': [[2, 7, 0x2000], [2, 15, 0x2004], [6, 7, 0x5000], [7, 7, 0xa000], [8, 7, 0xc000]],
                             'leaf_math_contract': [0x80, 0x88, 0x90, 8],
                             'allocation_body_bounds': [[0x2000, 7, 31], [0x7000, 7, 15], [0x8000, 7, 39]],
                             'array_body_contract': [0x6000, 2, 15, element_bytes, 1],
                             'array_length_layout': [2, 7, element_bytes, 1],
                             'stack_limit_offset': 0x60,
                             'thread_heap_classes': [[0xa8, 2]],
                             'predefined_allocations': [[0x6000, 2], [0x7000, 3], [0x8000, 4]],
                             'preserved_call_registers': [[0x7000, 1 << 2], [0x9000, 31]],
                             'nonreturning_calls': [[0xc000, 'range_error_without_fpu']],
                             'frame_preserving_calls': [[0x3000, 'stack_overflow_without_fpu'], [0x9000, 'array_write_barrier'], [0xa000, 'double_to_integer']]}
            if native_returns:
                audit['native_return_sdk'] = [[17, 5, 'Internal_allocateOneByteString', 'allocate_one_byte_string'],
                                              [23, 6, 'Internal_allocateTwoByteString', 'allocate_two_byte_string']]
                audit['native_return_identities'] = [
                    {'entry': entry, 'code_entry': entry, 'payload': entry, 'end': entry+8, 'is_native': True,
                     'owns_code': True, 'recognized_kind': kind, 'native_name': name, 'library_uri': 'dart:_internal'}
                    for entry, kind, name in [(0xd000, 17, 'Internal_allocateOneByteString'),
                                              (0xe000, 23, 'Internal_allocateTwoByteString')]]
            def verify(value):
                return check_receivers(value, read, lambda raw, address: list(decoder.disasm(raw, address)), audit)
            if name == 'prefix-interior-dispatch-entries':
                assert len(result['prefix_call_effects']) == 2, 'Interior helper proofs missing'
                for defect in ('missing-parent', 'wrong-parent', 'unrecorded-entry', 'legacy-scope', 'legacy-format', 'boolean-parent'):
                    forged = copy.deepcopy(result)
                    effect = forged['prefix_call_effects'][0]
                    if defect == 'missing-parent': effect.pop('containing_payload')
                    elif defect == 'wrong-parent': effect['containing_payload'] = 0x5000
                    elif defect == 'unrecorded-entry':
                        forged['dispatch_table']['entries'] = [None if v == effect['payload'] else v for v in forged['dispatch_table']['entries']]
                    elif defect == 'legacy-scope': forged['call_effects'].extend(forged['prefix_call_effects'])
                    elif defect == 'legacy-format': forged['format'] = 21
                    elif defect == 'boolean-parent': effect['containing_payload'] = True
                    try:
                        verify(forged)
                    except (AssertionError, KeyError):
                        passed.append('prefix-interior-tamper-'+defect)
                    else:
                        raise AssertionError('Accepted forged interior-entry proof: '+defect)
            if name == 'prefix-helper-budget-boundary':
                for defect in ('missing', 'duplicate', 'argument-slot', 'result-slot'):
                    forged = copy.deepcopy(result)
                    if defect == 'missing': forged['prefix_call_effects'] = []
                    elif defect == 'duplicate': forged['prefix_call_effects'] *= 2
                    elif defect == 'argument-slot': forged['prefix_call_effects'][0]['array_return']['array_sp_offset'] = 0
                    elif defect == 'result-slot': forged['prefix_call_effects'][0]['array_return']['index_sp_offset'] = 8
                    try:
                        verify(forged)
                    except (AssertionError, KeyError):
                        passed.append('prefix-helper-tamper-'+defect)
                    else:
                        raise AssertionError('Accepted forged supplemental proof: '+defect)
            if name == 'result-use-tagged-header':
                for defect in ('getter', 'stop', 'blocks', 'scope', 'class', 'target', 'continuation', 'promoted'):
                    forged = copy.deepcopy(result)
                    c = forged['array_result_traces'][0]
                    if defect == 'getter': c['trace']['getter'] += 4
                    elif defect == 'stop': c['trace']['stop'] -= 4
                    elif defect == 'blocks': c['trace']['blocks'].append(c['trace']['blocks'][-1])
                    elif defect == 'scope': c['scope'] = 'entry_prefix'
                    elif defect == 'class': c['indexed_returns'][0]['class_id'] += 1
                    elif defect == 'target': c['resolutions'][0]['snapshot_target'] += 4
                    elif defect == 'continuation':
                        block = next(b for b in c['certificate']['blocks'] if b['start'] == c['trace']['getter']+4)
                        block['array_continuation'] = c['trace']['getter']
                    elif defect == 'promoted':
                        forged['array_entry_traces'] = forged['array_result_traces']
                        forged['array_result_traces'] = []
                    try:
                        verify(forged)
                    except (AssertionError, KeyError):
                        passed.append('result-use-tamper-'+defect)
                    else:
                        raise AssertionError('Accepted forged result use: '+defect)
            if name == 'entry-prefix-first-result-4':
                for defect in ('stop', 'repeat', 'omit-block', 'guard-offset', 'guard-stub', 'guard-missing', 'index', 'class', 'binding', 'scope', 'promoted'):
                    forged = copy.deepcopy(result)
                    c = forged['array_entry_traces'][0]
                    claim = c['indexed_returns'][0]
                    if defect == 'stop': c['trace']['stop'] += 4
                    elif defect == 'repeat': c['trace']['blocks'].append(c['trace']['blocks'][0])
                    elif defect == 'omit-block': del c['trace']['blocks'][1]
                    elif defect == 'guard-offset': c['trace']['stack_checks'][0]['site'] += 4
                    elif defect == 'guard-stub': c['trace']['stack_checks'][0]['stub'] += 4
                    elif defect == 'guard-missing': c['trace']['stack_checks'] = []
                    elif defect == 'index': claim['index'] = 1
                    elif defect == 'class': claim['class_id'] += 1
                    elif defect == 'binding': claim['entry_input_sp_offset'] += 8
                    elif defect == 'scope': c['scope'] = 'entry_chain'
                    elif defect == 'promoted':
                        forged['array_contexts'] = forged['array_entry_traces']
                        forged['array_entry_traces'] = []
                    try:
                        verify(forged)
                    except (AssertionError, KeyError):
                        passed.append('entry-prefix-tamper-'+defect)
                    else:
                        raise AssertionError('Accepted forged entry trace: '+defect)
            if name == 'stack-path-element-and-dispatch':
                for defect in ('edge', 'site', 'successor', 'slow_path', 'stub', 'proof', 'offset', 'scope', 'missing', 'promoted'):
                    forged = copy.deepcopy(result)
                    c = forged['array_path_contexts'][0]
                    condition = c['path_condition']
                    if defect == 'edge': condition['edge'] = 'taken'
                    elif defect in ('site', 'successor', 'slow_path', 'stub'): condition[defect] += 4
                    elif defect == 'proof': condition['proof'] = condition['proof'][:-1]
                    elif defect == 'offset': forged['receiver_metadata']['stack_limit_offset'] += 8
                    elif defect == 'scope': c['scope'] = 'entry_chain'
                    elif defect == 'missing': del c['path_condition']
                    elif defect == 'promoted':
                        forged['array_contexts'] = forged['array_path_contexts']
                        forged['array_path_contexts'] = []
                    try:
                        verify(forged)
                    except (AssertionError, KeyError):
                        passed.append('stack-path-tamper-'+defect)
                    else:
                        raise AssertionError('Accepted forged path condition: '+defect)

            verify(result)
            if name == 'length-call-bound-array':
                for defect in ('scope', 'origin', 'slot', 'value', 'status', 'continuation'):
                    forged = copy.deepcopy(result)
                    context = next(c for c in forged['array_contexts'] if c['array_length_returns'])
                    claim = context['array_length_returns'][0]
                    if defect == 'scope': context['scope'] = 'entry_block'
                    elif defect == 'origin': claim['entry_input_sp_offset'] = 8
                    elif defect == 'slot': claim['input_sp_offset'] = 8
                    elif defect == 'value': claim['value'] = '0x6'
                    elif defect == 'status': context['status'] = 'length_proved'
                    else: next(b for b in context['certificate']['blocks'] if b.get('array_continuation') is not None)['array_continuation'] = None
                    try:
                        verify(forged)
                    except AssertionError:
                        passed.append('length-context-certificate-reject-' + defect)
                    else:
                        raise AssertionError('Forged contextual length application accepted: ' + defect)
            if name == 'length-call-local-array-4':
                for defect in ('value', 'length', 'callee', 'slot', 'allocation', 'origin', 'proof', 'mask', 'callee-certificate', 'continuation', 'missing-continuation'):
                    forged = copy.deepcopy(result)
                    edge = next(e for e in forged['edges'] if e.get('array_length_return'))
                    claim = edge['array_length_return']
                    if defect == 'value': claim['value'] = '0x6'
                    elif defect == 'length': claim['length'] = 3
                    elif defect == 'callee': claim['callee'] += 4
                    elif defect == 'slot': claim['input_sp_offset'] = 8
                    elif defect == 'allocation': claim['allocation'] += 4
                    elif defect == 'origin': claim['allocation'] = None; claim['entry_input_sp_offset'] = 0
                    elif defect == 'proof': claim['proof'].remove(edge['site'])
                    elif defect == 'mask': next(c['array_length'] for c in forged['call_effects'] if c['payload'] == claim['callee'])['written_registers'] = 0
                    elif defect == 'callee-certificate': forged['call_effects'] = [c for c in forged['call_effects'] if c['payload'] != claim['callee']]
                    else:
                        block = next(b for c in forged['receiver_certificates'] if c['payload'] == 0x1000 for b in c['blocks'] if b.get('array_continuation') is not None)
                        block['array_continuation'] = block['array_continuation']-4 if defect == 'continuation' else None
                    try:
                        verify(forged)
                    except AssertionError:
                        passed.append('length-call-certificate-reject-' + defect)
                    else:
                        raise AssertionError('Forged length application accepted: ' + defect)
            if name == 'array-length-4-16':
                for defect in ('class', 'slot', 'result', 'representation', 'effect', 'fault', 'proof', 'layout', 'audit', 'legacy'):
                    forged = copy.deepcopy(result)
                    claim = next(c['array_length'] for c in forged['call_effects'] if c.get('array_length'))
                    if defect == 'class': claim['array_class_id'] += 1
                    elif defect == 'slot': claim['array_sp_offset'] = 0
                    elif defect == 'result': claim['result_register'] = 'x1'
                    elif defect == 'representation': claim['result_representation'] = 'smi'
                    elif defect == 'effect': claim['heap_effect'] = 'unknown'
                    elif defect == 'fault': claim['may_fault'] = False
                    elif defect == 'proof': claim['proof'].pop()
                    elif defect == 'layout': forged['receiver_metadata']['array_length_layout'][1] += 4
                    elif defect == 'audit': forged['receiver_metadata']['array_length_layout'][2] = 8
                    else: forged['format'] = 15
                    try:
                        verify(forged)
                    except AssertionError:
                        passed.append('array-length-certificate-reject-' + defect)
                    else:
                        raise AssertionError('Forged length contract accepted: ' + defect)
            if name == 'indexed-result-4-0':
                for defect in ('class', 'index', 'allocation', 'callee', 'duplicate', 'missing-certificate', 'legacy'):
                    forged = copy.deepcopy(result)
                    edge = next(e for e in forged['edges'] if e.get('indexed_return'))
                    if defect == 'duplicate': forged['edges'].append(copy.deepcopy(edge))
                    elif defect == 'missing-certificate': forged['receiver_certificates'] = []
                    elif defect == 'legacy': forged['format'] = 13
                    else: edge['indexed_return'][{'class': 'class_id'}.get(defect, defect)] += 1
                    try:
                        verify(forged)
                    except AssertionError:
                        passed.append('indexed-certificate-reject-' + defect)
                    else:
                        raise AssertionError('Forged indexed claim accepted: ' + defect)

            if name == 'array-context-distinct-caller-contents':
                for defect in ('class', 'binding-class', 'index', 'caller', 'length', 'array-slot', 'read-slot', 'register', 'status', 'certificate', 'proof', 'duplicate-context', 'duplicate-read', 'legacy', 'missing-caller-certificate'):
                    forged = copy.deepcopy(result)
                    ctx = next(c for c in forged['array_contexts'] if c['status'] == 'read_proved')
                    if defect == 'class': ctx['array_reads'][0]['class_id'] += 1
                    elif defect == 'binding-class': ctx['array_input']['elements'][0][1] += 1
                    elif defect == 'index': ctx['array_reads'][0]['index'] += 1
                    elif defect == 'caller': ctx['callers'] += next(c['callers'] for c in forged['array_contexts'] if c is not ctx)
                    elif defect == 'length': ctx['array_input']['length'] += 1
                    elif defect == 'array-slot': ctx['array_input']['sp_offset'] = 8
                    elif defect == 'read-slot': ctx['array_reads'][0]['input_sp_offset'] = 8
                    elif defect == 'register': ctx['array_reads'][0]['register'] = 'x3'
                    elif defect == 'status': ctx['status'] = 'bound_only'
                    elif defect == 'certificate': ctx['certificate'] = None
                    elif defect == 'proof': ctx['array_reads'][0]['proof'] = []
                    elif defect == 'duplicate-context': forged['array_contexts'].append(copy.deepcopy(ctx))
                    elif defect == 'duplicate-read': ctx['array_reads'] *= 2
                    elif defect == 'legacy': forged['format'] = 14
                    else: forged['receiver_certificates'] = []
                    try:
                        verify(forged)
                    except AssertionError:
                        passed.append('array-context-certificate-reject-' + defect)
                    else:
                        raise AssertionError('Forged array context accepted: ' + defect)
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
        # Authored identity-return bodies. Their input is a physical entry slot,
        # not a guessed source parameter or return type.
        forward_caller = prologue + ['ldr x2, [x27, #40]', 'str x2, [x15]', 'bl 0x5000', 'mov x2, x0'] + dispatch[:-1] + epilogue
        def forwarding(data, payload=0x5000):
            return next((c.get('return_input') for c in data['call_effects'] if c['payload'] == payload), None)
        for name, body, slot in [
            ('leaf', ['ldr x0, [x15]', 'ret'], 0),
            ('copy', ['ldr x4, [x15]', 'mov x0, x4', 'ret'], 0),
            ('paired', ['ldp x0, x1, [x15]', 'ret'], 0),
            ('local-spill', prologue + ['ldr x4, [x29, #16]', 'stur x4, [x29, #-8]', 'ldur x0, [x29, #-8]'] + epilogue, 0),
            ('two-returns', ['cbz x1, 0x5010', 'ldr x0, [x15]', 'ret', 'nop', 'ldr x0, [x15]', 'ret'], 0),
        ]:
            d = run('result-forwards-' + name, forward_caller, {0x5000: body})
            assert forwarding(d) == slot and len(resolved(d)) == 1, name
            claim = next(e['forwarded_return'] for e in d['edges'] if e.get('forwarded_return'))
            assert claim['class_id'] == 1 and claim['input_sp_offset'] == slot and claim['register'] == 'x0'
        for name, body in [
            ('narrow-load', ['ldr w0, [x15]', 'ret']),
            ('narrow-copy', ['ldr x0, [x15]', 'mov w0, w0', 'ret']),
            ('unaligned', ['ldur x0, [x15, #1]', 'ret']),
            ('outside-window', ['ldr x0, [x15, #256]', 'ret']),
            ('modified-input', ['ldr x0, [x15]', 'add x0, x0, #1', 'ret']),
            ('different-return-slots', ['cbz x1, 0x5010', 'ldr x0, [x15]', 'ret', 'nop', 'ldr x0, [x15, #8]', 'ret']),
            ('converged-conflict', ['ldr x0, [x15]', 'cbz x1, 0x5010', 'ldr x0, [x15, #8]', 'b 0x5014', 'nop', 'ret']),
            ('unproved-link', ['ldr x0, [x15]', 'mov x30, x9', 'ret']),
            ('caller-input-write', ['str x1, [x15]', 'ldr x0, [x15]', 'ret']),
            ('calls-are-not-bit-identity', prologue + ['ldr x0, [x29, #16]', 'bl 0x2000'] + epilogue),
        ]:
            d = run('result-refuses-' + name, forward_caller, {0x5000: body})
            assert forwarding(d) is None and not any(e.get('forwarded_return') for e in d['edges']), name
            assert not resolved(d), name
        d = run('result-input-beyond-slot-zero',
                prologue + ['ldr x2, [x27, #40]', 'str x2, [x15, #8]', 'bl 0x5000', 'mov x2, x0'] + dispatch[:-1] + epilogue,
                {0x5000: ['ldr x0, [x15, #8]', 'ret']})
        assert forwarding(d) == 8 and len(resolved(d)) == 1
        d = run('result-interior-call-remains-unknown',
                prologue + ['ldr x2, [x27, #40]', 'str x2, [x15]', 'bl 0x5004', 'mov x2, x0'] + dispatch[:-1] + epilogue,
                {0x5000: ['ldr x0, [x15]', 'ret']})
        assert not resolved(d) and not any(e.get('forwarded_return') for e in d['edges'])
        # Caller classes are separate contexts, including return-only contexts.
        outer = prologue + ['ldr x2, [x27, #40]', 'str x2, [x15]', 'bl 0x4000'] + epilogue
        other = prologue + ['ldr x2, [x27, #56]', 'str x2, [x15]', 'bl 0x4000'] + epilogue
        wrapper = prologue + ['ldr x2, [x29, #16]', 'str x2, [x15]', 'bl 0x5000'] + epilogue
        d = run('result-contexts-retain-distinct-caller-classes', outer,
                {0x3000: other, 0x4000: wrapper, 0x5000: ['ldr x0, [x15]', 'ret']})
        contexts = [c for c in d['call_contexts'] if c['payload'] == 0x4000]
        assert len(contexts) == 2 and {c['forwarded_returns'][0]['class_id'] for c in contexts} == {1, 2}
        assert all(not c['resolutions'] for c in contexts)
        large = prologue + ['sub x15, x15, #1024', 'ldr x0, [x29, #16]'] + [f'str x0, [x15, #{i*8}]' for i in range(128)] + epilogue
        d = run('result-input-cache-does-not-exhaust-frame-proof', forward_caller, {0x5000: large})
        assert forwarding(d) == 0 and len(resolved(d)) == 1
        # Fresh-array identities and contents never cross a branch or call.
        allocate = prologue + ['mov x2, #4', 'bl 0x6000']
        write = ['ldr x3, [x27, #40]', 'stur w3, [x0, #15]']
        read = ['ldur w4, [x0, #15]', 'add x2, x4, x28, lsl #32']
        for name, middle in [
            ('compressed', write + read),
            ('copy-root', write + ['mov x5, x0', 'ldur w4, [x5, #15]', 'add x2, x4, x28, lsl #32']),
            ('derived-root', write + ['add x5, x0, #15', 'ldr w4, [x5]', 'add x2, x4, x28, lsl #32']),
            ('stack-root', write + ['str x0, [x15]', 'ldr x5, [x15]', 'ldur w4, [x5, #15]', 'add x2, x4, x28, lsl #32']),
            ('paired-store', ['ldr x3, [x27, #40]', 'add x5, x0, #15', 'stp w3, w3, [x5]'] + read),
            ('packed-copy', write + ['ldur w4, [x0, #15]', 'mov w5, w4', 'add x2, x5, x28, lsl #32']),
            ('disjoint-write', write + ['sturb w9, [x0, #19]'] + read),
            ('replace-with-known', write + ['ldr x3, [x27, #48]', 'stur w3, [x0, #15]'] + read),
        ]:
            d = run('array-element-' + name, allocate + middle + dispatch[:-1] + epilogue)
            assert len(resolved(d)) == 1, name
            if name == 'stack-root':
                assert 0x1000 + (len(allocate) + len(write)) * 4 in resolved(d)[0]['proof']
        for name, middle in [
            ('partial-write', write + ['sturb w9, [x0, #16]'] + read),
            ('unknown-element', ['stur w9, [x0, #15]'] + read),
            ('smi-not-object', ['mov x3, #2', 'stur w3, [x0, #15]'] + read),
            ('unwritten-slot', write + ['ldur w4, [x0, #19]', 'add x2, x4, x28, lsl #32']),
            ('unaligned-load', write + ['ldur w4, [x0, #16]', 'add x2, x4, x28, lsl #32']),
            ('oversized-load', write + ['ldur x2, [x0, #15]']),
            ('truncated-root', write + ['mov w5, w0', 'ldur w4, [x5, #15]', 'add x2, x4, x28, lsl #32']),
            ('wrong-decompression', write + ['ldur w4, [x0, #15]', 'add x2, x4, x28, lsl #16']),
            ('changed-heap-register', write + ['ldur w4, [x0, #15]', 'mov x28, #0', 'add x2, x4, x28, lsl #32']),
            ('indexed-write', write + ['str w9, [x0, x10]', 'ldur w4, [x0, #15]', 'add x2, x4, x28, lsl #32']),
            ('header-write', write + ['stur w9, [x0, #-1]'] + read),
            ('body-overrun', write + ['stur w9, [x0, #23]'] + read),
            ('verified-call', write + ['bl 0x9000'] + read),
            ('new-allocation', write + ['mov x2, #4', 'bl 0x6000'] + read),
            ('branch', write + ['b 0x1100'] + ['nop'] * (64-len(allocate)-len(write)-1) + read),
        ]:
            d = run('array-refuses-' + name, allocate + middle + dispatch[:-1] + epilogue)
            assert not resolved(d), name
        d = run('array-arguments-partial-elements', allocate + write + ['str x0, [x15]', 'bl 0x4000'] + epilogue)
        argument = next(e['array_arguments'][0] for e in d['edges'] if e['array_arguments'])
        assert argument['length'] == 2 and argument['elements'] == [[0, 1]]
        for name, length in [('odd', 3), ('negative', -2), ('bounded', 66), ('empty', 0)]:
            d = run('array-refuses-length-' + name,
                    prologue + [f'mov x2, #{length}', 'bl 0x6000'] + write + read + dispatch[:-1] + epilogue)
            assert not resolved(d), name
        d = run('array-post-allocation-external-entry', allocate + write + read + dispatch[:-1] + epilogue,
                {0x4000: ['b 0x1014']})
        assert not resolved(d) and not any(e['array_arguments'] for e in d['edges'])
        d = run('array-full-width-elements', allocate + ['ldr x3, [x27, #40]', 'stur x3, [x0, #15]', 'ldur x2, [x0, #15]'] + dispatch[:-1] + epilogue, element_bytes=8)
        assert len(resolved(d)) == 1
        # A conditional length relation is stronger than a frame-only proof.
        def length_summary(data):
            return next((c.get('array_length') for c in data['call_effects'] if c['payload'] == 0x5000), None)
        for width in (4, 8):
            for slot in (0, 16, 248):
                body = [f'ldr x3, [x15, #{slot}]', f'ldur {"w0" if width == 4 else "x0"}, [x3, #7]', 'ret']
                d = run(f'array-length-{width}-{slot}', ['bl 0x5000'], {0x5000: body}, element_bytes=width)
                claim = length_summary(d)
                assert claim and claim['array_sp_offset'] == slot and claim['array_class_id'] == 2
                assert claim['heap_effect'] == 'read_only' and claim['may_fault'] is True
        simple_length = ['ldr x3, [x15, #16]', 'ldur w0, [x3, #7]', 'ret']
        d = run('array-length-copied-input-and-result', ['bl 0x5000'],
                {0x5000: ['mov x5, x15', 'ldr x3, [x5, #16]', 'ldur w2, [x3, #7]', 'mov x0, x2', 'ret']})
        assert length_summary(d)
        for name, body in [
            ('wrong-field', [simple_length[0], 'ldur w0, [x3, #15]', 'ret']),
            ('wrong-width', [simple_length[0], 'ldur x0, [x3, #7]', 'ret']),
            ('signed-field', [simple_length[0], 'ldursw x0, [x3, #7]', 'ret']),
            ('narrow-input', ['ldr w3, [x15, #16]'] + simple_length[1:]),
            ('outside-input-window', ['ldr x3, [x15, #256]'] + simple_length[1:]),
            ('clobbered-result', simple_length[:-1] + ['mov x0, x9', 'ret']),
            ('heap-write', simple_length[:-1] + ['stur w9, [x3, #15]', 'ret']),
            ('returning-call', prologue + ['bl 0x3000'] + ['ldr x3, [x29, #32]', simple_length[1]] + epilogue),
            ('frame-writes', prologue + ['ldr x3, [x29, #32]', simple_length[1]] + epilogue),
            ('branch', simple_length[:-1] + ['cbz x9, 0x500c', 'ret']),
            ('alternate-return', simple_length[:-1] + ['ret x19']),
            ('trailing-code', simple_length + ['nop']),
        ]:
            d = run('array-length-reject-' + name, ['bl 0x5000'], {0x5000: body})
            assert length_summary(d) is None, name
            if name == 'frame-writes': assert any(c['payload'] == 0x5000 for c in d['call_effects'])
        def length_leaf(width=4, argument=0, pointer='x1'):
            return [f'ldr {pointer}, [x15, #{argument}]', f'ldur {"w0" if width == 4 else "x0"}, [{pointer}, #7]', 'ret']
        def length_claims(data):
            return [e['array_length_return'] for e in data['edges'] if e.get('array_length_return')]
        for width in (4, 8):
            prepare = allocate + ['ldr x3, [x27, #40]', f'stur {"w3" if width == 4 else "x3"}, [x0, #15]', 'mov x8, x0', 'str x8, [x15]']
            consume = [f'ldur {"w4" if width == 4 else "x2"}, [x8, #15]'] + (['add x2, x4, x28, lsl #32'] if width == 4 else [])
            d = run(f'length-call-local-array-{width}', prepare + ['bl 0x5000', 'mov x6, x0'] + consume + dispatch[:-1] + epilogue,
                    {0x5000: length_leaf(width)}, element_bytes=width)
            assert len(length_claims(d)) == 1 and length_claims(d)[0]['length'] == 2 and length_claims(d)[0]['value'] == '0x4'
            assert len(resolved(d)) == 1 and any(b.get('array_continuation') is not None for c in d['receiver_certificates'] if c['payload'] == 0x1000 for b in c['blocks'])
        prepare = allocate + write + ['mov x8, x0', 'str x8, [x15]']
        consume = ['ldur w4, [x8, #15]', 'add x2, x4, x28, lsl #32'] + dispatch[:-1] + epilogue
        d = run('length-call-repeated-leaves', prepare + ['bl 0x5000', 'bl 0x5000'] + consume, {0x5000: length_leaf()})
        assert len(length_claims(d)) == 2 and len(resolved(d)) == 1
        d = run('length-call-reload-clobbered-root', prepare + ['bl 0x5000', 'ldr x8, [x15]'] + consume, {0x5000: length_leaf(pointer='x8')})
        assert len(length_claims(d)) == 1 and len(resolved(d)) == 1
        d = run('length-call-empty-array', prologue + ['mov x2, #0', 'bl 0x6000', 'str x0, [x15]', 'bl 0x5000'] + epilogue, {0x5000: length_leaf()})
        assert len(length_claims(d)) == 1 and length_claims(d)[0]['length'] == 0
        continuation_address = 0x1000+(len(prepare)+1)*4
        d = run('length-call-external-return-entry', prepare + ['bl 0x5000'] + consume,
                {0x5000: length_leaf(), 0x4000: [f'b {hex(continuation_address)}']})
        assert len(length_claims(d)) == 1 and not resolved(d)
        d = run('length-call-backedge-return-entry', prepare + ['bl 0x5000'] + consume[:-3] +
                [f'cbz x9, {hex(continuation_address)}'] + consume[-3:], {0x5000: length_leaf()})
        assert len(length_claims(d)) == 1 and not resolved(d)
        d = run('length-call-drops-packed-handoff', prepare + ['ldur w9, [x8, #15]', 'bl 0x5000', 'add x2, x9, x28, lsl #32'] + dispatch[:-1] + epilogue,
                {0x5000: length_leaf()})
        assert len(length_claims(d)) == 1 and not resolved(d)
        for name, before, after, leaf in [
            ('wrong-class', ['ldr x3, [x27, #40]', 'str x3, [x15]'], [], length_leaf()),
            ('same-class-other-identity', ['ldr x3, [x27, #56]', 'str x3, [x15]'], [], length_leaf()),
            ('partial-argument', ['sturb w9, [x15, #1]'], [], length_leaf()),
            ('wrong-slot', [], [], length_leaf(argument=8)),
            ('clobbered-root-register', [], [], length_leaf(pointer='x8')),
            ('unknown-call', [], ['bl 0x3000'], length_leaf()),
            ('changed-element', [], ['sturb w9, [x8, #16]'], length_leaf()),
            ('branch-boundary', [], [f'b {hex(0x1000+(len(prepare)+2)*4)}'], length_leaf()),
        ]:
            d = run('length-call-reject-' + name, prepare + before + ['bl 0x5000'] + after + consume, {0x5000: leaf})
            assert not resolved(d), name
            if name in ('wrong-class', 'same-class-other-identity', 'partial-argument', 'wrong-slot'): assert not length_claims(d), name
        indirect_length = ['mov x0, #4', 'ldr x30, [x21, x0, lsl #3]', 'blr x30']
        d = run('length-call-indirect-target', prepare + indirect_length + consume, {0xb000: length_leaf()})
        assert len(length_claims(d)) == 1 and length_claims(d)[0]['callee'] == 0xb000 and len(resolved(d)) == 2
        d = run('length-call-does-not-preserve-lr', prepare + indirect_length + ['blr x30'] + epilogue, {0xb000: length_leaf()})
        assert len(length_claims(d)) == 1 and len(resolved(d)) == 1
        # Conditional input-to-element summaries, independent authored getters.
        def array_summary(data):
            return next((c.get('array_return') for c in data['call_effects'] if c['payload'] == 0x5000), None)
        def getter(element_bytes=4):
            return ['ldr x2, [x15, #8]', 'ldr x4, [x15]', 'sbfx x5, x4, #1, #31',
                    f'add x16, x2, x5, lsl #{2 if element_bytes == 4 else 3}',
                    f'ldur {"w0" if element_bytes == 4 else "x0"}, [x16, #15]'] + (
                    ['add x0, x0, x28, lsl #32'] if element_bytes == 4 else []) + ['ret']
        def indexed_caller(index=0, length=2, width=4):
            return prologue + [f'mov x2, #{length*2}', 'bl 0x6000', 'ldr x3, [x27, #40]',
                               f'add x6, x0, #{index*width}', f'stur {"w3" if width == 4 else "x3"}, [x6, #15]',
                               f'mov x4, #{index*2}', 'stp x4, x0, [x15]']
        consumer = ['bl 0x5000', 'mov x2, x0'] + dispatch[:-1] + epilogue
        for width in (4, 8):
            for index, length in ((0, 2), (1, 2), (31, 32)):
                d = run(f'indexed-result-{width}-{index}', indexed_caller(index, length, width) + consumer,
                        {0x5000: getter(width)}, element_bytes=width)
                assert len(resolved(d)) == 1 and array_summary(d)['array_sp_offset'] == 8
                claim = next(e['indexed_return'] for e in d['edges'] if e.get('indexed_return'))
                assert claim['class_id'] == 1 and claim['index'] == index
        framed = prologue + ['ldr x2, [x29, #24]', 'ldr x4, [x29, #16]'] + getter()[2:-1] + epilogue
        d = run('indexed-result-frame-coordinate-inputs', indexed_caller() + consumer, {0x5000: framed})
        assert array_summary(d) and len(resolved(d)) == 1
        narrow_index = getter()[:2] + ['mov w4, w4'] + getter()[2:]
        d = run('indexed-result-bounded-smi-word-copy', indexed_caller() + consumer, {0x5000: narrow_index})
        assert array_summary(d) and len(resolved(d)) == 1
        unscaled_inputs = ['ldur x2, [x15, #8]', 'ldur x4, [x15]'] + getter()[2:]
        d = run('indexed-result-unscaled-entry-loads', indexed_caller() + consumer, {0x5000: unscaled_inputs})
        assert array_summary(d) and len(resolved(d)) == 1
        overlapping_base = ['mov x2, x15', 'ldr x2, [x2, #8]'] + getter()[1:]
        d = run('indexed-result-load-overwrites-base', indexed_caller() + consumer, {0x5000: overlapping_base})
        assert array_summary(d) and len(resolved(d)) == 1
        indirect = ['mov x0, #4', 'ldr x30, [x21, x0, lsl #3]', 'blr x30', 'mov x2, x0'] + dispatch[:-1] + epilogue
        d = run('indexed-result-proved-indirect-callee', indexed_caller() + indirect, {0xb000: getter()})
        assert len(resolved(d)) == 2 and any(e.get('indexed_return', {}).get('callee') == 0xb000 for e in d['edges'] if e.get('indexed_return'))
        # The boxed branch is infeasible only under the explicit Smi condition.
        boxed = ['ldr x2, [x15, #8]', 'ldr x4, [x15]', 'sbfx x5, x4, #1, #31',
                 'tbz w4, #0, 0x5014', 'ldur x5, [x4, #7]'] + getter()[3:]
        d = run('indexed-result-smi-prunes-boxed-branch', indexed_caller() + consumer, {0x5000: boxed})
        assert array_summary(d) and len(resolved(d)) == 1
        alternate = boxed[:3] + ['tbnz w4, #0, 0x5024'] + getter()[3:] + ['mov x0, #0', 'ret']
        d = run('indexed-result-tbnz-prunes-boxed-branch', indexed_caller() + consumer, {0x5000: alternate})
        assert array_summary(d) and len(resolved(d)) == 1
        checked = getter()[:3] + ['cmp x5, #2', 'b.hs 0x5028'] + getter()[3:] + ['nop', 'nop'] + ['stp x29, x30, [x15, #-16]!', 'bl 0xc000']
        # Keep error target independent of the getter's instruction count.
        checked[4] = f'b.hs {hex(0x5000+(len(checked)-2)*4)}'
        d = run('indexed-result-audited-exceptional-exit', indexed_caller() + consumer, {0x5000: checked})
        assert array_summary(d) and len(resolved(d)) == 1
        for name, body in [
            ('wrong-stride', getter()[:3]+['add x16, x2, x5, lsl #3']+getter()[4:]),
            ('wrong-data-offset', getter()[:4]+['ldur w0, [x16, #19]']+getter()[5:]),
            ('missing-decompression', getter()[:5]+['ret']),
            ('wrong-heap-register', getter()[:5]+['add x0, x0, x27, lsl #32', 'ret']),
            ('wrong-decompression-shift', getter()[:5]+['add x0, x0, x28, lsl #31', 'ret']),
            ('wrong-index-slot', getter()[:1]+['ldr x4, [x15, #16]']+getter()[2:]),
            ('wrong-untag', getter()[:2]+['sbfx x5, x4, #2, #30']+getter()[3:]),
            ('narrow-input-pointer', ['ldr w2, [x15, #8]']+getter()[1:]),
            ('signed-element-load', getter()[:4]+['ldursw x0, [x16, #15]']+getter()[5:]),
            ('byte-element-load', getter()[:4]+['ldurb w0, [x16, #15]']+getter()[5:]),
            ('halfword-element-load', getter()[:4]+['ldurh w0, [x16, #15]']+getter()[5:]),
            ('wrong-element-width', getter()[:4]+['ldur x0, [x16, #15]']+getter()[5:]),
            ('alternate-return-register', getter()[:-1]+['ret x19']),
            ('heap-write', getter()[:3]+['stur w9, [x2, #15]']+getter()[3:]),
            ('returning-call', prologue+['bl 0x3000']+getter()[:-1]+epilogue),
            ('conflicting-return', getter()[:-1]+['cbz x8, 0x5020', 'ret', 'mov x0, #0', 'ret']),
            ('unproved-bit', boxed[:3]+['tbz w4, #1, 0x5014']+boxed[4:]),
        ]:
            d = run('indexed-result-reject-'+name, indexed_caller()+consumer, {0x5000: body})
            assert not resolved(d) and not any(e.get('indexed_return') for e in d['edges']), name
            if name != 'wrong-index-slot': assert array_summary(d) is None, name
        for name, change in [
            ('negative-index', ['mov x4, #-2', 'str x4, [x15]']),
            ('boxed-index', ['mov x4, #1', 'str x4, [x15]']),
            ('outside-length', ['mov x4, #4', 'str x4, [x15]']),
            ('outside-summary-bound', ['mov x4, #64', 'str x4, [x15]']),
            ('unknown-index', ['str x9, [x15]']),
            ('partial-index', ['sturb w9, [x15, #1]']),
            ('partial-root', ['sturb w9, [x15, #9]']),
            ('unknown-array-element', ['stur w9, [x0, #15]']),
            ('intervening-call', ['bl 0x3000']),
            ('branch-boundary', ['b 0x102c']),
        ]:
            d = run('indexed-result-caller-reject-'+name, indexed_caller()+change+consumer, {0x5000: getter()})
            assert array_summary(d) and not resolved(d) and not any(e.get('indexed_return') for e in d['edges']), name
        # Input contents are a conditional entry-block view, not a global type.
        def bound_caller(pool_offset=40, width=4, length=2, stores=None, target=0x5000):
            return prologue + [f'mov x2, #{length*2}', 'bl 0x6000', f'ldr x3, [x27, #{pool_offset}]',
                               f'stur {"w3" if width == 4 else "x3"}, [x0, #15]'] + (stores or ['str x0, [x15]']) + [f'bl {hex(target)}'] + epilogue
        def bound_body(width=4, offset=15, prefix=None):
            return prologue + (prefix or []) + ['ldr x8, [x29, #16]', f'ldur {"w9" if width == 4 else "x2"}, [x8, #{offset}]'] + (
                ['add x2, x9, x28, lsl #32'] if width == 4 else []) + dispatch[:-1] + epilogue
        def bound_contexts(data):
            return [c for c in data['array_contexts'] if c['payload'] == 0x5000]
        length_body = prologue + ['ldr x8, [x29, #16]', 'str x8, [x15]', 'bl 0xb000', 'mov x6, x0',
                                  'ldur w9, [x8, #15]', 'add x2, x9, x28, lsl #32'] + dispatch[:-1] + epilogue
        # Restrict one analysis to a named fast edge; the ordinary view still
        # includes the runtime slow path and must keep its previous uncertainty.
        def guarded_body(check=None, tail=None):
            prefix = prologue + (check or ['ldr x16, [x26, #0x60]', 'cmp x15, x16'])
            fast = 0x5000+(len(prefix)+1)*4
            body = (tail if tail is not None else length_body[len(prologue):])
            slow = fast+len(body)*4
            return prefix + [f'b.ls {hex(slow)}'] + body + ['bl 0x3000', f'b {hex(fast)}']
        for width in (4, 8):
            body = guarded_body(tail=['ldr x8, [x29, #16]', 'str x8, [x15]', 'bl 0xb000'] + epilogue)
            d = run('stack-path-length-'+str(width), bound_caller(width=width),
                    {0x5000: body, 0xb000: length_leaf(width)}, element_bytes=width)
            assert bound_contexts(d)[0]['status'] == 'bound_only'
            paths = d['array_path_contexts']
            assert len(paths) == 1 and paths[0]['scope'] == 'initial_stack_check_fast_path'
            assert paths[0]['status'] == 'length_proved' and len(paths[0]['array_length_returns']) == 1
            assert not length_claims(d) and not resolved(d)
        d = run('stack-path-element-and-dispatch', bound_caller(),
                {0x5000: guarded_body(), 0xb000: length_leaf()})
        path = d['array_path_contexts'][0]
        assert bound_contexts(d)[0]['status'] == 'bound_only' and not resolved(d)
        assert path['status'] == 'read_proved' and len(path['resolutions']) == len(path['array_reads']) == 1
        for name, check in [
            ('wrong-offset', ['ldr x16, [x26, #0x68]', 'cmp x15, x16']),
            ('wrong-width', ['ldr w16, [x26, #0x60]', 'cmp x15, x16']),
            ('wrong-base', ['ldr x16, [x25, #0x60]', 'cmp x15, x16']),
            ('wrong-compare', ['ldr x16, [x26, #0x60]', 'cmp x14, x16']),
            ('shifted-compare', ['ldr x16, [x26, #0x60]', 'cmp x15, x16, lsl #1']),
        ]:
            d = run('stack-path-reject-'+name, bound_caller(),
                    {0x5000: guarded_body(check), 0xb000: length_leaf()})
            assert not d['array_path_contexts']
        for name, mutate, extra in [
            ('wrong-stub', lambda b: b[:-2]+['bl 0x9000', b[-1]], {}),
            ('wrong-edge', lambda b: [x.replace('b.ls', 'b.hi') for x in b], {}),
            ('wrong-return', lambda b: b[:-1]+['b 0x5000'], {}),
            ('alternate-fast-entry', lambda b: b, {0x4000: ['b 0x5018']}),
            ('alternate-prefix-entry', lambda b: b, {0x4000: ['b 0x500c']}),
        ]:
            d = run('stack-path-reject-'+name, bound_caller(),
                    {0x5000: mutate(guarded_body()), 0xb000: length_leaf(), **extra})
            assert not d['array_path_contexts']
        d = run('length-call-bound-array', bound_caller(), {0x5000: length_body, 0xb000: length_leaf()})
        ctx = bound_contexts(d)[0]
        assert ctx['status'] == 'read_proved' and ctx['scope'] == 'entry_chain' and len(ctx['array_length_returns']) == 1
        assert ctx['array_length_returns'][0]['allocation'] is None and ctx['array_length_returns'][0]['entry_input_sp_offset'] == 0
        assert len(ctx['array_reads']) == 1 and len(ctx['resolutions']) == 1
        d = run('length-call-bound-return-alternate-entry', bound_caller(),
                {0x5000: length_body, 0xb000: length_leaf(), 0x4000: ['b 0x5018']})
        ctx = bound_contexts(d)[0]
        assert ctx['status'] == 'length_proved' and not ctx['array_reads'] and not ctx['resolutions']
        d = run('length-call-bound-length-only', bound_caller(),
                {0x5000: prologue + ['ldr x8, [x29, #16]', 'str x8, [x15]', 'bl 0xb000'] + epilogue, 0xb000: length_leaf()})
        ctx = bound_contexts(d)[0]
        assert ctx['status'] == 'length_proved' and len(ctx['array_length_returns']) == 1 and not ctx['array_reads']
        def entry_body(index='mov x5, #0', bound='cmp x5, x3', offset=0x60, before=None, after=None, getter_call=None, length_call=None):
            body, labels = [], {}
            def label(name): labels[name] = 0x5000+len(body)*4
            body += prologue + ['ldr x16, [x26, #0x60]', 'cmp x15, x16', 'b.ls @slow_a']
            label('fast')
            body += ['ldr x8, [x29, #16]', 'str x8, [x15]'] + (length_call or ['bl 0xb000']) + ['sbfx x3, x0, #1, #31', index]
            label('loop')
            body += [f'ldr x16, [x26, #{offset}]', 'cmp x15, x16', 'b.ls @slow_b']
            label('bound')
            body += [bound, 'b.ge @done', 'sbfiz x4, x5, #1, #31', 'cmp x5, x4, asr #1', 'b.eq @tagged', 'bl 0x3000']
            label('tagged')
            body += (before or []) + ['stp x4, x8, [x15]'] + (getter_call or ['bl 0xb100'])
            for text in after or []:
                if text.endswith(':'): label(text[:-1])
                else: body.append(text)
            body += ['b @loop']
            label('done')
            body += epilogue
            label('slow_a')
            body += ['bl 0x3000', 'b @fast']
            label('slow_b')
            body += ['bl 0x3000', 'b @bound']
            return [re.sub(r'@([a-z_]+)', lambda m: hex(labels[m[1]]), text) for text in body]
        for width in (4, 8):
            d = run('entry-prefix-first-result-'+str(width), bound_caller(width=width),
                    {0x5000: entry_body(), 0xb000: length_leaf(width), 0xb100: getter(width)}, element_bytes=width)
            traces = d['array_entry_traces']
            assert len(traces) == 1 and traces[0]['scope'] == 'entry_prefix'
            claim = traces[0]['indexed_returns'][0]
            assert claim['index'] == 0 and claim['class_id'] == 1 and claim['allocation'] is None and claim['entry_input_sp_offset'] == 0
            assert len(traces[0]['trace']['stack_checks']) == 1
            assert not any(e.get('indexed_return') for e in d['edges'])
            assert bound_contexts(d)[0]['status'] == 'bound_only'
        split_body = entry_body()
        split_site = 0x5000+4*next(n for n, text in enumerate(split_body) if text.startswith('b.ge '))
        d = run('entry-prefix-reject-split-comparison', bound_caller(),
                {0x5000: split_body, 0xb000: length_leaf(), 0xb100: getter(), 0x4000: [f'b {hex(split_site)}']})
        assert not d['array_entry_traces']
        escaping = [re.sub(r'^b.ge .*', 'b.ge 0xf000', text) for text in entry_body(bound='cmp x5, x9')]
        d = run('entry-prefix-reject-unknown-escaping-branch', bound_caller(),
                {0x5000: escaping, 0xb000: length_leaf(), 0xb100: getter()})
        assert not d['array_entry_traces']
        for name, entry_options in [
            ('unknown-index', {'index': 'mov x5, x9'}),
            ('unknown-bound', {'bound': 'cmp x5, x9'}),
            ('out-of-bounds', {'index': 'mov x5, #2'}),
            ('negative-index', {'index': 'mov x5, #-1'}),
            ('unmatched-second-guard', {'offset': 0x68}),
            ('intervening-call', {'before': ['bl 0x3000']}),
            ('fresh-array-is-not-entry-input', {'before': ['mov x2, #4', 'bl 0x6000', 'ldr x3, [x27, #40]', 'stur w3, [x0, #15]', 'mov x8, x0', 'mov x4, #0']}),
            ('overwritten-element', {'before': ['sturb w9, [x8, #15]']}),
        ]:
            d = run('entry-prefix-reject-'+name, bound_caller(),
                    {0x5000: entry_body(**entry_options), 0xb000: length_leaf(), 0xb100: getter()})
            assert not d['array_entry_traces'], name
        def run_result_uses():
            direct = ['mov x2, x0'] + dispatch[:-1]
            for width in (4, 8):
                for pool_offset, cid in ((40, 1), (56, 2)):
                    d = run(f'result-use-direct-{width}-{cid}', bound_caller(pool_offset, width),
                            {0x5000: entry_body(after=direct), 0xb000: length_leaf(width), 0xb100: getter(width)}, element_bytes=width)
                    uses = d['array_result_traces']
                    assert len(uses) == 1 and uses[0]['scope'] == 'entry_result_use'
                    assert uses[0]['indexed_returns'][0]['class_id'] == cid
                    assert uses[0]['trace']['getter'] == uses[0]['indexed_returns'][0]['site']
                    assert uses[0]['trace']['stop'] == uses[0]['resolutions'][0]['site']
                    assert uses[0]['resolutions'][0]['index'] == cid
                    assert d['array_entry_traces'][0]['trace']['stop'] == uses[0]['trace']['getter']
            tagged = ['mov x1, #7', 'tbz w0, #0, @class_join', 'ldur x1, [x0, #-1]', 'ubfx x1, x1, #8, #16',
                      'class_join:', 'str x0, [x15]', 'mov x5, x1', 'ldr x30, [x21, x5, lsl #3]', 'blr x30']
            d = run('result-use-tagged-header', bound_caller(), {0x5000: entry_body(after=tagged), 0xb000: length_leaf(), 0xb100: getter()})
            assert len(d['array_result_traces']) == 1
            header = ['ldur x1, [x0, #-1]', 'ubfx x1, x1, #8, #16']
            for name, change in [('word-copy', ['mov w5, w1']), ('partial-constant', ['mov x5, x1', 'movk x5, #0, lsl #16'])]:
                d = run('result-use-'+name, bound_caller(), {0x5000: entry_body(after=header+change+['ldr x30, [x21, x5, lsl #3]', 'blr x30']), 0xb000: length_leaf(), 0xb100: getter()})
                assert len(d['array_result_traces']) == 1
            for name, after in [
                ('overwritten-result', ['mov x0, #0']+direct),
                ('same-class-other-object', ['ldr x2, [x27, #40]']+dispatch[:-1]),
                ('constant-target', ['mov x0, #1', 'ldr x30, [x21, x0, lsl #3]', 'blr x30']),
                ('intervening-runtime-call', ['bl 0x3000']+direct),
                ('intervening-indirect-call', ['mov x5, #4', 'ldr x30, [x21, x5, lsl #3]', 'blr x30']+direct),
                ('narrow-object-copy', ['mov w2, w0']+dispatch[:-1]),
                ('untracked-spill-provenance', ['stur x0, [x29, #-8]', 'ldur x2, [x29, #-8]']+dispatch[:-1]),
                ('unknown-alias-store', ['str x9, [x10]']+direct),
                ('unknown-branch', ['cbz x9, @uncertain', 'uncertain:']+direct),
                ('target-overwrite', header+['ldr x30, [x21, x1, lsl #3]', 'mov x30, #0', 'blr x30']),
                ('constant-class-overwrite', header+['mov x1, #1', 'ldr x30, [x21, x1, lsl #3]', 'blr x30']),
            ]:
                d = run('result-use-reject-'+name, bound_caller(), {0x5000: entry_body(after=after), 0xb000: length_leaf(), 0xb100: getter()})
                assert not d['array_result_traces'], name
                assert len(d['array_entry_traces']) == 1
        run_result_uses()
        def run_late_helpers():
            indirect = ['mov x5, #5', 'ldr x30, [x21, x5, lsl #3]', 'blr x30']
            body = entry_body(after=['mov x2, x0']+dispatch[:-1], getter_call=indirect)
            d = run('prefix-helper-budget-boundary', bound_caller(),
                    {0x4000: bound_caller(), 0x5000: body, 0xb000: length_leaf(), 0x40000: getter()}, late_helper=True)
            assert d['call_effect_analysis']['attempted'] == 16384
            assert not any(c['payload'] == 0x40000 for c in d['call_effects'])
            assert [c['payload'] for c in d['prefix_call_effects']] == [0x40000]
            assert d['prefix_effect_analysis']['attempted'] == d['prefix_effect_analysis']['accepted'] == 1
            assert len(d['array_entry_traces']) == len(d['array_result_traces']) == 1
            assert len(d['array_result_traces'][0]['callers']) == 2
            late_length_body = entry_body(after=['mov x2, x0']+dispatch[:-1], getter_call=indirect,
                                         length_call=['mov x5, #6', 'ldr x30, [x21, x5, lsl #3]', 'blr x30'])
            d = run('prefix-helper-two-round-dependency', bound_caller(),
                    {0x5000: late_length_body, 0x40100: length_leaf(), 0x40000: getter()}, late_helper=True)
            assert d['call_effect_analysis']['attempted'] == 16384
            assert [c['payload'] for c in d['prefix_call_effects']] == [0x40000, 0x40100]
            assert d['prefix_effect_analysis']['rounds'] == 2
            assert d['prefix_effect_analysis']['attempted'] == d['prefix_effect_analysis']['accepted'] == 2
            assert len(d['array_entry_traces']) == len(d['array_result_traces']) == 1
            d = run('prefix-helper-reject-mutating-body', bound_caller(),
                    {0x5000: body, 0xb000: length_leaf(), 0x40000: ['ldr x2, [x15, #8]', 'stur w9, [x2, #15]']+getter()}, late_helper=True)
            assert not d['prefix_call_effects'] and not d['array_entry_traces'] and not d['array_result_traces']
        run_late_helpers()

        def run_interior_helpers():
            prefix = ['br x16'] + ['nop']*5
            length_call = ['mov x5, #4', 'ldr x30, [x21, x5, lsl #3]', 'blr x30']
            getter_call = ['mov x5, #5', 'ldr x30, [x21, x5, lsl #3]', 'blr x30']
            body = entry_body(after=['mov x2, x0']+dispatch[:-1], getter_call=getter_call, length_call=length_call)
            d = run('prefix-interior-dispatch-entries', bound_caller(),
                    {0x4000: bound_caller(), 0x5000: body, 0xb000: prefix+length_leaf(), 0xb100: prefix+getter()}, helper_entry_offset=24)
            assert [(c['payload'], c['containing_payload']) for c in d['prefix_call_effects']] == [(0xb018, 0xb000), (0xb118, 0xb100)]
            assert not any(c.get('array_length') or c.get('array_return') for c in d['call_effects'])
            assert not any(n['start'] in (0xb018, 0xb118) for n in d['nodes'])
            assert len(d['array_entry_traces']) == len(d['array_result_traces']) == 1
            assert len(d['array_result_traces'][0]['callers']) == 2
            for name, helpers, offset in [
                ('write', {0xb000: prefix+['ldr x1, [x15]', 'stur w9, [x1, #15]']+length_leaf(), 0xb100: prefix+getter()}, 24),
                ('escaping-branch', {0xb000: prefix+['b 0xb000']+length_leaf(), 0xb100: prefix+getter()}, 24),
                ('unaligned-entry', {0xb000: prefix+length_leaf(), 0xb100: prefix+getter()}, 26),
            ]:
                d = run('prefix-interior-reject-'+name, bound_caller(), {0x5000: body, **helpers}, helper_entry_offset=offset)
                assert not d['prefix_call_effects'] and not d['array_entry_traces'] and not d['array_result_traces'], name
            direct = entry_body(after=['mov x2, x0']+dispatch[:-1], getter_call=getter_call, length_call=['bl 0xb01c'])
            d = run('prefix-interior-reject-unrecorded-direct-entry', bound_caller(),
                    {0x5000: direct, 0xb000: prefix+['nop']+length_leaf(), 0xb100: prefix+getter()}, helper_entry_offset=24)
            assert not d['prefix_call_effects'] and not d['array_entry_traces'] and not d['array_result_traces']
            large_body = entry_body(after=['mov x2, x0']+dispatch[:-1], getter_call=['bl 0xb300'], length_call=length_call)
            d = run('prefix-interior-small-suffix-large-container', bound_caller(),
                    {0x5000: large_body, 0xb000: ['br x16']+['nop']*69+length_leaf(), 0xb300: getter()}, helper_entry_offset=280)
            assert [(c['payload'], c['containing_payload']) for c in d['prefix_call_effects']] == [(0xb118, 0xb000)]
            assert len(d['array_entry_traces']) == len(d['array_result_traces']) == 1
        run_interior_helpers()

        d = run('array-context-distinct-caller-contents', bound_caller(), {0x4000: bound_caller(56), 0x5000: bound_body()})
        ctx = bound_contexts(d)
        assert len(ctx) == 2 and all(c['status'] == 'read_proved' for c in ctx)
        assert {c['array_reads'][0]['class_id'] for c in ctx} == {1, 2}
        assert all(len(c['resolutions']) == 1 for c in ctx) and not resolved(d)
        d = run('array-context-equal-contents-share-binding', bound_caller(), {0x4000: bound_caller(), 0x5000: bound_body()})
        assert len(bound_contexts(d)) == 1 and len(bound_contexts(d)[0]['callers']) == 2
        d = run('array-context-length-keeps-bindings-distinct', bound_caller(), {0x4000: bound_caller(length=3), 0x5000: bound_body()})
        assert {c['array_input']['length'] for c in bound_contexts(d)} == {2, 3}
        d = run('array-context-full-word-element', bound_caller(width=8), {0x5000: bound_body(width=8)}, element_bytes=8)
        assert bound_contexts(d)[0]['array_reads'][0]['class_id'] == 1
        d = run('array-context-derived-input-pointer', bound_caller(),
                {0x5000: prologue + ['ldr x8, [x29, #16]', 'add x8, x8, #4', 'ldur w9, [x8, #11]', 'add x2, x9, x28, lsl #32'] + dispatch[:-1] + epilogue})
        assert bound_contexts(d)[0]['status'] == 'read_proved'
        d = run('array-context-empty-leaf-prologue', bound_caller(),
                {0x5000: ['ldr x8, [x15]', 'ldur w9, [x8, #15]', 'add x0, x9, x28, lsl #32', 'ret']})
        assert bound_contexts(d)[0]['array_reads'][0]['register'] == 'x0'
        d = run('array-context-known-replacement', bound_caller(),
                {0x5000: prologue + ['ldr x8, [x29, #16]', 'ldr x3, [x27, #56]', 'stur w3, [x8, #15]', 'ldur w9, [x8, #15]', 'add x2, x9, x28, lsl #32'] + dispatch[:-1] + epilogue})
        assert bound_contexts(d)[0]['array_reads'][0]['class_id'] == 2
        for name, body in [
            ('unknown-slot', bound_body(offset=19)),
            ('call-before-read', bound_body(prefix=['bl 0x3000'])),
            ('verified-call-before-read', bound_body(prefix=['bl 0x7000'])),
            ('overwritten-entry-slot', bound_body(prefix=['str xzr, [x29, #16]'])),
            ('partial-entry-slot', bound_body(prefix=['sturb w3, [x29, #17]'])),
            ('partial-element', prologue + ['ldr x8, [x29, #16]', 'sturb w3, [x8, #16]', 'ldur w9, [x8, #15]', 'add x2, x9, x28, lsl #32'] + dispatch[:-1] + epilogue),
            ('unknown-element-store', prologue + ['ldr x8, [x29, #16]', 'stur w3, [x8, #15]', 'ldur w9, [x8, #15]', 'add x2, x9, x28, lsl #32'] + dispatch[:-1] + epilogue),
            ('header-store', prologue + ['ldr x8, [x29, #16]', 'stur w3, [x8, #-1]', 'ldur w9, [x8, #15]', 'add x2, x9, x28, lsl #32'] + dispatch[:-1] + epilogue),
            ('narrow-array-pointer', prologue + ['ldr w8, [x29, #16]', 'ldur w9, [x8, #15]', 'add x2, x9, x28, lsl #32'] + dispatch[:-1] + epilogue),
            ('wrong-expansion', prologue + ['ldr x8, [x29, #16]', 'ldur w9, [x8, #15]', 'add x2, x9, x28, lsl #31'] + dispatch[:-1] + epilogue),
            ('unknown-pointer-offset', prologue + ['ldr x8, [x29, #16]', 'add x8, x8, x10', 'ldur w9, [x8, #15]', 'add x2, x9, x28, lsl #32'] + dispatch[:-1] + epilogue),
            ('branch-boundary', prologue + ['ldr x8, [x29, #16]', 'b 0x5014', 'ldur w9, [x8, #15]', 'add x2, x9, x28, lsl #32'] + dispatch[:-1] + epilogue),
            ('entry-backedge', bound_body()[:-1] + ['cbz x11, 0x5000', 'ret']),
        ]:
            d = run('array-context-bound-only-'+name, bound_caller(), {0x5000: body})
            assert bound_contexts(d) and all(c['status'] == 'bound_only' and c['certificate'] is None for c in bound_contexts(d)), name
        same_array_twice = ['stp x0, x0, [x15]']
        d = run('array-context-two-input-slots', bound_caller(stores=same_array_twice),
                {0x5000: prologue + ['ldr x8, [x29, #16]', 'ldur w9, [x8, #15]', 'add x2, x9, x28, lsl #32',
                                   'ldr x8, [x29, #24]', 'ldur w9, [x8, #15]', 'add x3, x9, x28, lsl #32'] + epilogue})
        ctx = bound_contexts(d)
        assert len(ctx) == 2 and {c['array_input']['sp_offset'] for c in ctx} == {0, 8}
        assert all(len(c['array_reads']) == 1 for c in ctx)
        d = run('array-context-does-not-assume-inputs-disjoint', bound_caller(stores=same_array_twice),
                {0x5000: prologue + ['ldr x8, [x29, #16]', 'ldr x10, [x29, #24]', 'stur w11, [x10, #15]',
                                   'ldur w9, [x8, #15]', 'add x2, x9, x28, lsl #32'] + dispatch[:-1] + epilogue})
        assert len(bound_contexts(d)) == 2 and all(c['status'] == 'bound_only' for c in bound_contexts(d))
        d = run('array-context-interior-target-skipped', bound_caller(target=0x5004), {0x5000: bound_body()})
        assert not bound_contexts(d)
        chain = {0x5000+i*0x100: prologue + [f'bl {hex(0x5100+i*0x100)}'] + epilogue for i in range(8)}
        chain[0x5800] = leaf
        d = run('callee-depth-bound', call_spill, chain)
        assert not resolved(d) and all(c['depth'] <= 8 for c in d['call_effects'])
        native_bodies = {0xd000: ['svc #0', 'ret'], 0xe000: ['svc #0', 'ret']}
        native_dispatch = ['ldur w0, [x0, #-1]', 'ubfx x0, x0, #8, #16', 'ldr x30, [x21, x0, lsl #3]', 'blr x30']
        for name, target, middle, expected in [
            ('one', 0xd000, [], 0x2000), ('two', 0xe000, [], 0x2004),
            ('overwrite', 0xd000, ['mov x0, x2'], None), ('unknown-call', 0xd000, ['bl 0x5000'], None)]:
            d = run('native-return-'+name, [f'bl {target:#x}'] + middle + native_dispatch,
                    native_bodies | {0x5000: ['ret']}, native_returns=True)
            values = [e['static_dispatch']['snapshot_target'] for e in d['edges'] if e.get('static_dispatch')]
            assert values == ([] if expected is None else [expected])
            assert sum(e.get('native_return') is not None for e in d['edges']) == 1
        d = run('native-return-caller-spill-killed',
                prologue + ['ldr x0, [x27, #40]', 'stur x0, [x29, #-8]', 'bl 0xd000',
                            'ldur x0, [x29, #-8]'] + native_dispatch, native_bodies, native_returns=True)
        assert not resolved(d) and all(e['payload'] not in (0xd000, 0xe000) for e in d['call_effects'])
        from register_context_cases import exercise_register_contexts
        exercise_register_contexts(run)
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
