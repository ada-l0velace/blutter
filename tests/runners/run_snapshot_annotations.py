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
from check_call_result_notes import expected_facts, check_stream


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--memcheck', action='store_true', help='Use ordinary binaries under Valgrind instead of sanitizers')
    parser.add_argument('--compare-compact', action='store_true', help='Compare compact/full facts and assembly for every fixture')
    parser.add_argument('--saved-only', action='store_true', help='Run saved async reference cases only')
    parser.add_argument('--fields-only', action='store_true', help='Run async field identity cases only')
    parser.add_argument('--fresh-only', action='store_true', help='Run fresh field initialization cases only')
    parser.add_argument('--closures-only', action='store_true', help='Run closure capture transfer controls only')
    parser.add_argument('--joined-only', action='store_true', help='Run bounded suspension-alternative reference cases only')
    parser.add_argument('--entry-reads-only', action='store_true', help='Run callee-entry container read cases only')
    parser.add_argument('--contents-only', action='store_true', help='Run selected fresh-content survival cases only')
    parser.add_argument('--captures-only', action='store_true', help='Run captured field local preservation cases only')
    parser.add_argument('--field-inputs-only', action='store_true', help='Run role-proven field input cases only')
    parser.add_argument('--futures-only', action='store_true', help='Run async Future binding cases only')
    parser.add_argument('--completions-only', action='store_true', help='Run async completion cases only')
    parser.add_argument('--inputs-only', action='store_true', help='Run supplied-input and provenance cases only')
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
                        str(root / 'blutter/src/AsyncOrigins.cpp'),
                        str(root / 'blutter/src/CompletionAnalysis.cpp'),
                        str(root / 'blutter/src/AsyncFutureBindings.cpp'),
                        str(root / 'blutter/src/SavedAsyncReferences.cpp'),
                        str(root / 'blutter/src/FieldBranchUses.cpp'),
                        str(root / 'blutter/src/FieldDecisions.cpp'),
                        str(root / 'blutter/src/ClosureCaptureTransfers.cpp'),
                        str(root / 'blutter/src/AsyncFieldAccesses.cpp'),
                        str(root / 'blutter/src/FieldInputOrigins.cpp'),
                        str(root / 'blutter/src/CapturedFieldValues.cpp'),
                        str(root / 'blutter/src/FreshFieldInitializations.cpp'),
                        str(root / 'blutter/src/FreshContentUses.cpp'),
                        str(root / 'blutter/src/CalleeEntryReads.cpp'),
                        str(root / 'blutter/src/WordOrigins.cpp'),
                        str(root / 'blutter/src/CallInputOrigins.cpp'),
                        str(root / 'blutter/src/ReceiverAnalysis.cpp'),
                        str(root / 'blutter/src/RegisterContexts.cpp'),
                        str(root / 'blutter/src/CallResultContexts.cpp'),
                        str(root / 'blutter/src/SdkStubResultAnalysis.cpp'),
                        str(root / 'blutter/src/CallResultAnnotations.cpp'),
                        str(root / 'blutter/src/CallInputRoles.cpp'),
                        str(root / 'blutter/src/CallInputShapes.cpp'),
                        str(root / 'blutter/src/DescriptorPrologue.cpp'),
                        str(root / 'blutter/src/CallEffects.cpp'),
                        str(root / 'blutter/src/NativeIr.cpp'),
                        str(root / 'blutter/src/Arm64Ir.cpp'),
                        str(root / 'blutter/src/ArrayLengthAnalysis.cpp'),
                        str(root / 'blutter/src/StackCheckAnalysis.cpp'),
                        '-o', str(executable)] + flags, check=True)

        def run(name, assembly, extra=None, suffix=b'', element_bytes=4, late_helper=False, helper_entry_offset=0, native_returns=False, selected_caller=None, sdk_stub_returns=False, async_contracts=False, stub_inputs="", call_inputs="", completions="", future_bindings="", saved_refs="", closure_captures=""):
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
            environment = dict(os.environ, BLUTTER_TEST_GRAPH_COMPACT='0', BLUTTER_TEST_ARRAY_BYTES=str(element_bytes), BLUTTER_TEST_LATE_HELPER='1' if late_helper else '0',
                BLUTTER_TEST_HELPER_ENTRY_OFFSET=str(helper_entry_offset),
                BLUTTER_TEST_NATIVE_RETURNS='1' if native_returns else '0',
                BLUTTER_TEST_SDK_STUB_RETURNS='1' if sdk_stub_returns else '0',
                BLUTTER_TEST_CLOSURE_CAPTURES=closure_captures, BLUTTER_TEST_SAVED_REFERENCES=saved_refs, BLUTTER_TEST_FUTURE_BINDINGS=future_bindings, BLUTTER_TEST_COMPLETIONS=completions, BLUTTER_TEST_STUB_INPUTS=stub_inputs, BLUTTER_TEST_CALL_INPUTS=call_inputs,
                BLUTTER_TEST_ASYNC_CONTRACTS='1' if async_contracts else '0',
                BLUTTER_TEST_ANALYSIS_CALLER='' if selected_caller is None else hex(selected_caller),
                ASAN_OPTIONS=f'halt_on_error=1:detect_leaks={leaks}', UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
            subprocess.run(command, check=True, env=environment)
            result = json.loads((temp / 'out.json').read_text())
            if args.compare_compact:
                from compact_graph_cases import check_compact
                check_compact(command, environment, temp / 'out.json', result)
            with (temp / 'out.json.asm').open() as assembly:
                rendered, _ = check_stream(assembly, expected_facts(result))
            assert set(rendered) == expected_facts(result), 'Missing authored assembly result annotations'
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
            audit = {'closure_capture_layout':dict(slot_bytes=0,tag=0,first_local_offset=0,context_offsets=[]),
                     'closure_entry_models':[], 'closure_capture_stack_maps':[], 'decision_branch_abi': dict(value_bit=4), 'field_decision_abi': dict(supported=True, true_offset=32, false_offset=48), 'heap_bits_register': 'x28' if element_bytes == 4 else None, 'word_return_register': 'x0', 'pool_heap_classes': [[3, 1], [4, 1], [5, 2]], 'class_allocations': [[0x2000, 1]],
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
            if sdk_stub_returns:
                audit.update(sdk_stub_return_sdk=[['allocate_growable_array', 5]],
                             sdk_stub_return_reference={'entry': 0xf000, 'end': 0xf008, 'kind': 'allocate_growable_array'},
                             sdk_stub_return_identities=[{'entry': 0xf000, 'payload': 0xf000, 'end': 0xf008,
                                                          'kind': 'allocate_growable_array'}],
                             known_stubs=[{'entry': 0xf000, 'size': 8}])
            audit.update(stub_input_abis=[], stub_input_references=[], stub_input_identities=[])
            if stub_inputs:
                modern = stub_inputs in ('new', 'field-inputs')
                field_inputs = stub_inputs.startswith('field-inputs')
                closure_kind = 'allocate_closure_2' if modern else 'allocate_closure'
                closure_inputs = [{'register':'x1','role':'closure_function'},
                                  {'register':'x3' if modern else 'x2','role':'closure_context'}]
                if modern: closure_inputs.append({'register':'x2','role':'closure_length_flags'})
                for entry, kind, inputs in [(0x1a000 if field_inputs else 0x11000,'allocate_array',[{'register':'x2','role':'array_length'}, {'register':'x1','role':'array_type_arguments'}]),
                                            (0x1b000 if field_inputs else 0x12000,closure_kind,closure_inputs)]:
                    raw = fixture_bytes[entry]
                    audit['stub_input_abis'].append(dict(kind=kind, inputs=inputs))
                    audit['stub_input_references'].append(dict(kind=kind, bytes=raw.hex()))
                    audit['stub_input_identities'].append(dict(entry=entry,payload=entry,end=entry+len(raw),kind=kind))
            if saved_refs == 'fields-fresh':
                audit['fresh_content_allocators'] = [0x7000]
                audit['class_allocations'].append([0x1c000, 7])
                audit['allocation_body_bounds'].append([0x1c000, 7, 31])
            from stub_input_roles import check_contracts
            check_contracts(result, audit, read)
            if call_inputs and call_inputs != 'unsupported':
                from call_input_shapes import check_shapes
                audit['call_input_abi'] = dict(supported=True, descriptor_register=4, word_bytes=8)
                audit['call_input_descriptors'] = [dict(pool_index=10, type_arguments=1 if call_inputs == 'mismatch' else 2, count=3, size=3, positional=3)]
                audit['function_metadata'] = [dict(entry=0x18000, name='authored', kind=0, call_input_model=dict(fixed=3, implicit=0, implicit_from_kind=0,
                    optional=0, type_parameters=2, parent_type_arguments=0, static=True, native=False, abstract=False, declared_types=['Object']*3))]
                prologue = call_inputs in ('prologue', 'named')
                audit['descriptor_prologue_abi'] = dict(supported=prologue, descriptor_register=4 if prologue else 0,
                    field_bytes=4 if prologue else 0, smi_shift=1 if prologue else 0,
                    type_arguments_offset=15 if prologue else 0, size_offset=23 if prologue else 0, frame_argument_base=16 if prologue else 0, count_offset=19 if prologue else 0)
                if prologue: audit['function_metadata'] = []
                if call_inputs == 'named':
                    audit['call_input_descriptors'][0].update(positional=1, named=[dict(index=1,name='first'),dict(index=2,name='last')])
                check_shapes(result, audit, read)
            if result.get('call_input_origins'):
                audit['input_object_catalog']=[dict(pool_index=3,kind='function',text='authored_capture' if closure_captures else 'authored_callback',entry=0x19000)]
                from input_origins import check_origins
                check_origins(result,audit,read)
            audit['future_binding_abi']=dict(supported=bool(future_bindings) and future_bindings!='unsupported',
                suspend_state_offset=-8 if future_bindings and future_bindings!='unsupported' else 0)
            if completions:
                audit['completion_exception_references'] = [dict(kind=kind, tail_only=tail, bytes=fixture_bytes[entry].hex()) for entry,kind,tail in
                    [(0x17000,'null_cast_without_fpu',False),(0x17100,'async_error',True)]]
                audit['completion_exception_identities'] = [dict(entry=entry,end=entry+len(fixture_bytes[entry]),kind=kind,tail_only=tail) for entry,kind,tail in
                    [(0x17000,'null_cast_without_fpu',False),(0x17100,'async_error',True)]]
                audit['completion_bodies'] = []
                if completions != 'missing':
                    for payload,raw in fixture_bytes.items():
                        audit['completion_bodies'].append(dict(payload=payload,end=payload+len(raw)+(4 if completions=='limited' and payload==0x1000 else 0),
                            available=True,async_error_handler=True,handlers=[0x1010] if completions=='handler' and payload==0x1000 else []))
                if future_bindings:
                    if future_bindings=='missing':audit['completion_bodies']=[]
                    elif future_bindings=='handler':
                        next(v for v in audit['completion_bodies'] if v['payload']==0x1000)['handlers']=[0x1004]
                from completion_summaries import check_completions
                check_completions(result,audit,read)
                if name == 'completion-direct':
                    for defect in ('class','site','proof','handler','body','exception','missing','duplicate','reached','status','steps','scope'):
                        forged=copy.deepcopy(result);summary=forged['completion_summaries'][0]
                        if defect=='class': summary['exact_class']+=1
                        elif defect=='site': summary['completions'][0]['site']+=4
                        elif defect=='proof': summary['completions'][0]['source']['proof']=[0x1000]
                        elif defect=='handler': forged['completion_bodies'][0]['handlers']=[0x1008]
                        elif defect=='body': forged['completion_bodies'][0]['end']+=4
                        elif defect=='exception': forged['completion_exception_contracts'][0]['entry']+=4
                        elif defect=='missing': summary['completions'].clear()
                        elif defect=='duplicate': summary['completions']*=2
                        elif defect=='reached': summary['reached'].pop()
                        elif defect=='status': summary['status']='null_only'
                        elif defect=='steps': summary['steps']+=1
                        else: summary['scope']='ordinary_return'
                        try: check_completions(forged,audit,read)
                        except (AssertionError,KeyError): passed.append('completion-forged-'+defect)
                        else: raise AssertionError('Forged completion accepted: '+defect)
                if name == 'completion-allocated-ldtr-null-clobber':
                    forged=copy.deepcopy(result);summary=forged['completion_summaries'][0]
                    summary.update(status='null_only',observed_null=True,unknown_value=False)
                    summary['completions'][0].update(value='null',basis='sdk_null_register',class_id=1,
                        source=dict(kind='runtime_null',site=0x1008,callee=None,bits=22,load=None,proof=[0x1008,0x100c]))
                    try:check_completions(forged,audit,read)
                    except AssertionError as error:
                        assert 'Canonical null register overwritten' in str(error)
                        passed.append('completion-ldtr-null-forgery-refused')
                    else:raise AssertionError('Overwritten null register accepted')
                if name in ('completion-forward','completion-zero','completion-handler-bypass'):
                    forged=copy.deepcopy(result);summary=forged['completion_summaries'][0]
                    summary.update(status='exact_heap_class',exact_class=2,closed=True)
                    try:check_completions(forged,audit,read)
                    except (AssertionError,KeyError):passed.append(name+'-promotion-refused')
                    else:raise AssertionError('Unsafe completion promotion accepted')
            else:
                from completion_summaries import check_completions
                check_completions(result,audit,read)
            from async_future_bindings import check_future_bindings,check_binding_stream
            try:check_future_bindings(result,audit,read)
            except AssertionError as error:raise AssertionError((name,str(error))) from error
            with (temp/'out.json.asm').open() as stream:check_binding_stream(result,stream)
            from saved_async_references import check_saved_references,check_saved_stream
            audit['saved_reference_abi']=dict(supported=bool(saved_refs and saved_refs!='unsupported'),first_local_offset=-8 if saved_refs and saved_refs!='unsupported' else 0)
            audit['saved_reference_stack_maps']=[]
            for edge in result['edges']:
                if edge['kind']!='call':continue
                available=saved_refs not in ('missing-map', 'fields-missing-map')
                audit['saved_reference_stack_maps'].append(dict(payload=edge['source'],site=edge['site'],available=available,spill_slots=32 if available else 0,
                    objects=[-8-bit*8 for bit in range(31,-1,-1) if saved_refs not in ('nonpointer', 'fields-nonpointer') or -8-bit*8!=-16] if available else []))
            if saved_refs == 'fields-gap':
                for m in audit['saved_reference_stack_maps']:
                    if m['available']:m.update(spill_slots=0, objects=[])
            audit['captured_field_register_slots'] = [[m['site'], 0 if m['available'] else None] for m in audit['saved_reference_stack_maps']]
            try:check_saved_references(result,audit,read)
            except AssertionError as error:raise AssertionError((name,str(error))) from error
            with (temp/'out.json.asm').open() as stream:check_saved_stream(result,stream)
            if saved_refs.startswith('fields'):
                audit['instance_field_abi'] = [1, 4, 8, 99, 8, 16]
                audit['instance_field_metadata'] = [[2, 32, 16, (1 << 6) | (1 << 7), 0, [[8, 'enabled', 'bool?']]]]
                if saved_refs == 'fields-fresh':audit['instance_field_metadata'].append([7, 32, 16, (1 << 6) | (1 << 7), 0, [[8, 'enabled', 'bool?']]])
            if closure_captures:
                legacy=closure_captures=='legacy'
                audit['closure_capture_layout']=dict(slot_bytes=4,tag=1,first_local_offset=-8,context_offsets=[['allocate_closure' if legacy else 'allocate_closure_2',19 if legacy else 35]])
                audit['closure_entry_models']=[] if closure_captures=='missing-model' else [
                    dict(pool_index=3,entry=0x19000,fixed=3 if closure_captures=='arity' else 2,entry_sp_offset=16 if closure_captures=='arity' else 8)]
                audit['instance_field_abi']=[1,4,8,99,8,16]
                audit['instance_field_metadata']=[[4,32,16,(1<<6)|(1<<7),0,[]]]
                audit.setdefault('completion_bodies',[]).append(dict(payload=0x19000,end=0x19000+len(fixture_bytes[0x19000]),available=closure_captures not in ('discarded','missing-body'),async_error_handler=False,handlers=[0x19018] if closure_captures=='handler' else []))
                if closure_captures=='discarded':
                    audit['tables']=[dict(first_with_code=1,entries=[dict(index=0,entry=0x19000)])]
                audit['closure_capture_stack_maps']=[dict(payload=0x19000,site=0x19024,
                    available=closure_captures!='missing-map',spill_slots=0 if closure_captures=='missing-map' else 1,
                    register_slots=None if closure_captures=='missing-map' else 0,
                    objects=[-8] if closure_captures not in ('missing-map','untagged') else [])]
            from async_field_accesses import check_fields, check_stream as check_field_stream
            check_fields(result, audit, read)
            with (temp/'out.json.asm').open() as stream:check_field_stream(result, stream)
            from field_input_origins import check_field_inputs, check_stream as check_field_input_stream
            check_field_inputs(result)
            with (temp/'out.json.asm').open() as stream:check_field_input_stream(result, stream)
            from captured_field_values import check_captures, check_stream as check_captured_stream
            check_captures(result, audit, read)
            if name == 'captured-tagged-local':
                for defect in ('slot', 'store', 'call', 'target', 'register', 'map', 'active-frame'):
                    forged = copy.deepcopy(result)
                    row = next(c for c in forged['captured_field_contexts'] if c['reloads'])
                    reload = row['reloads'][0]
                    if defect in ('slot', 'store', 'call', 'target'):reload[defect] += 8
                    elif defect == 'register':reload['register'] = 4
                    elif defect == 'map':forged['captured_field_stack_maps'][0]['objects'].remove(reload['slot'])
                    else:
                        frame = next(f for f in forged['saved_reference_frames'] if f['payload'] == 0x1000)
                        frame['points'] = [p for p in frame['points'] if p[0] != reload['site']]
                    try:check_captures(forged, audit, read)
                    except (AssertionError, KeyError):passed.append('captured-forged-' + defect)
                    else:raise AssertionError('Forged captured value proof accepted: ' + defect)
            with (temp/'out.json.asm').open() as stream:check_captured_stream(result, stream)
            from fresh_field_initializations import check_fresh_fields, check_stream as check_fresh_stream
            check_fresh_fields(result, audit, read)
            from fresh_content_uses import check_contents, check_stream as check_content_stream
            check_contents(result, audit, read)
            from joined_async_references import check_joined, check_stream as check_joined_stream
            check_joined(result, audit, read)
            with (temp/'out.json.asm').open() as stream:check_joined_stream(result, stream)
            from field_branch_uses import check_branches, check_stream as check_branch_stream, expected_notes
            check_branches(result, audit, read)
            if name == 'joined-field-tbnz':
                for defect in ('offset', 'bit', 'clear_target', 'reference', 'missing'):
                    forged = copy.deepcopy(result)
                    if defect == 'missing':
                        forged['field_branch_uses'].clear()
                    else:
                        forged['field_branch_uses'][0][defect] += 1
                    try:
                        check_branches(forged, audit, read)
                    except AssertionError:
                        passed.append('field-branch-forged-' + defect)
                    else:
                        raise AssertionError('Forged field branch accepted: ' + defect)
            expected_branches = expected_notes(result)
            with (temp/'out.json.asm').open() as stream:
                assert check_branch_stream(stream, expected_branches) == expected_branches
            from field_decisions import check_decisions, check_stream as check_decision_stream, expected_notes as decision_notes
            check_decisions(result, audit, read)
            if name == 'decision-base':
                for defect in ('bit-sense', 'comparison', 'slot', 'site', 'parent', 'missing', 'abi'):
                    forged = copy.deepcopy(result)
                    if defect == 'missing':
                        forged['field_decisions'].clear()
                    elif defect == 'abi':
                        forged['field_decision_abi']['true_offset'] += 16
                    else:
                        row = forged['field_decisions'][0]
                        if defect == 'bit-sense': row['on_set'] = not row['on_set']
                        elif defect == 'comparison': row['non_null_true'] = not row['non_null_true']
                        else: row[{'slot':'fp_offset', 'site':'site', 'parent':'branch_use'}[defect]] += 1
                    try:
                        check_decisions(forged, audit, read)
                    except AssertionError:
                        passed.append('decision-forged-' + defect)
                    else:
                        raise AssertionError('Forged field decision accepted: ' + defect)
            decision_expected = decision_notes(result)
            with (temp/'out.json.asm').open() as stream:
                assert check_decision_stream(stream, decision_expected) == decision_expected
            from decision_branch_uses import check_uses, check_stream as check_decision_uses, expected_notes as decision_use_notes
            check_uses(result,audit,read)
            if name == 'decision-saved-use':
                for defect in ('target','reload','definition','slot','map','bit','missing'):
                    forged = copy.deepcopy(result)
                    c = forged['decision_reference_contexts'][0]
                    if defect == 'target': forged['decision_branch_uses'][0]['true_target'] += 4
                    elif defect == 'reload': c['reloads'][0]['site'] += 4
                    elif defect == 'definition': c['reloads'][0]['store'] += 4
                    elif defect == 'slot': c['reloads'][0]['slot'] -= 8
                    elif defect == 'bit': forged['decision_branch_abi']['value_bit'] += 1
                    elif defect == 'missing': forged['decision_branch_uses'].clear()
                    else:
                        for m in forged['saved_reference_stack_maps']:
                            if -24 in m['objects']: m['objects'].remove(-24)
                    try: check_uses(forged,audit,read)
                    except (AssertionError,KeyError,IndexError):
                        passed.append('decision-use-forged-' + defect)
                    else: raise AssertionError('Forged decision use accepted: '+defect)
            expected_uses = decision_use_notes(result)
            with (temp/'out.json.asm').open() as stream:
                assert check_decision_uses(stream,expected_uses) == expected_uses
            from closure_capture_transfers import check_transfers, expected_notes as closure_notes, check_stream as check_closure_stream
            check_transfers(result,audit,read)
            if name == 'closure-base' and result['closure_capture_transfers']:
                for defect in ('source','destination','local','entry','map','missing'):
                    forged=copy.deepcopy(result)
                    if defect=='missing': forged['closure_capture_transfers'].clear()
                    else:
                        row=forged['closure_capture_transfers'][0]
                        if defect=='map': row['stack_map']['objects']=[]
                        else: row[{'source':'value_displacement','destination':'destination_offset','local':'saved_slot','entry':'entry_sp_offset'}[defect]]+=4
                    try:check_transfers(forged,audit,read)
                    except (AssertionError,KeyError,IndexError):passed.append('closure-forged-'+defect)
                    else:raise AssertionError('Forged closure transfer accepted: '+defect)
            closure_expected=closure_notes(result)
            with (temp/'out.json.asm').open() as stream:
                assert check_closure_stream(stream,closure_expected)==closure_expected
            from callee_entry_reads import check_entry_reads, check_stream as check_entry_stream
            check_entry_reads(result, audit, read)
            with (temp/'out.json.asm').open() as stream:check_entry_stream(result, stream)
            with (temp/'out.json.asm').open() as stream:check_content_stream(result, stream)
            if name == 'joined-optional':
                for defect in ('history', 'missing-alternative', 'store', 'slot', 'register', 'map', 'entry', 'source'):
                    forged=copy.deepcopy(result);row=next(c for c in forged['joined_reference_contexts'] if c['observations']);o=row['observations'][0];reader=read
                    if defect=='history':o['last_suspensions']=[None,o['last_suspensions'][1]+4]
                    elif defect=='missing-alternative':o['last_suspensions']=[o['last_suspensions'][1]]
                    elif defect=='store':o['store']+=4
                    elif defect=='slot':o['slot']-=8
                    elif defect=='register':o['register']+=1
                    elif defect=='map':next(m for m in forged['saved_reference_stack_maps'] if m['site']==o['last_suspensions'][1])['objects'].remove(o['slot'])
                    elif defect=='entry':forged['receiver_metadata']['entries'].append(o['site'])
                    else:row['source_await']+=4
                    try:check_joined(forged,audit,reader)
                    except (AssertionError,KeyError,IndexError):passed.append('joined-forged-'+defect)
                    else:raise AssertionError('Forged joined-reference proof accepted: '+defect)
            if name in ('entry-base', 'entry-guard') and result['callee_entry_read_contracts']:
                for defect in ('load-offset', 'load-width', 'load-register', 'prefix', 'scope', 'call-target', 'caller-word', 'guard'):
                    if defect == 'guard' and name != 'entry-guard':continue
                    forged = copy.deepcopy(result);row = forged['callee_entry_read_contracts'][0];reader = read
                    if defect == 'load-offset':row['reads'][0]['entry_sp_offset'] += 8
                    elif defect == 'load-width':row['reads'][0]['bytes'] = 4
                    elif defect == 'load-register':row['reads'][0]['register'] += 1
                    elif defect == 'prefix':row['prefix'].pop(1)
                    elif defect == 'scope':forged['container_entry_read_links'][0]['scope'] = 'source_parameter'
                    elif defect == 'guard':row['guard']['stub'] = 0x7000
                    else:
                        context = forged['fresh_content_contexts'][forged['container_entry_read_links'][0]['context']]
                        changed = context['transfer'] if defect == 'call-target' else context['transfer'] - 4
                        replacement = bytes.fromhex('00000094') if defect == 'call-target' else bytes.fromhex('e20500f9')
                        def reader(address, size):
                            data = bytearray(read(address, size))
                            if address <= changed and changed + 4 <= address + size:data[changed-address:changed-address+4] = replacement
                            return bytes(data)
                    try:check_entry_reads(forged, audit, reader)
                    except (AssertionError, KeyError, IndexError):passed.append(name + '-forged-' + defect)
                    else:raise AssertionError('Forged callee-entry proof accepted: ' + defect)
            if name == 'contents-mint-diamond':
                for defect in ('path', 'role', 'allocator', 'registers', 'entry', 'seed', 'branch-store'):
                    forged = copy.deepcopy(result)
                    row = next(c for c in forged['fresh_content_contexts'] if c['inputs'])
                    f = forged['fresh_field_contexts'][row['initialization']]
                    pc = f['write']['site'];reader = read
                    if defect == 'path':
                        row['proof'].remove(pc + 8);row['steps'] -= 1
                        forged['fresh_content_work']['steps'] -= 1;forged['fresh_content_work']['remaining'] += 1
                    elif defect == 'role':forged['call_input_origins'][row['inputs'][0]]['role'] = 'register_observation'
                    elif defect == 'allocator':forged['fresh_content_allocators'] = []
                    elif defect == 'registers':forged['receiver_metadata']['preserved_call_registers'][0][1] = 1
                    elif defect == 'entry':forged['receiver_metadata']['entries'].append(pc + 16)
                    elif defect == 'seed':f['write'].update(offset=20, index=1)
                    else:
                        # Replace the auxiliary Mint store on just one path with
                        # an overwrite of the selected array element.
                        changed = pc + 12
                        def reader(address, size):
                            data = bytearray(read(address, size))
                            if address <= changed and changed + 4 <= address + size:
                                data[changed-address:changed-address+4] = bytes.fromhex('43f000b8')
                            return bytes(data)
                    try:check_contents(forged, audit, reader)
                    except (AssertionError, KeyError, IndexError):passed.append('contents-forged-' + defect)
                    else:raise AssertionError('Forged selected-content proof accepted: ' + defect)
            if name == 'fresh-array-element':
                for defect in ('offset', 'index', 'base', 'register', 'length', 'bits', 'allocation-alias'):
                    forged = copy.deepcopy(result);row = next(c for c in forged['fresh_field_contexts'] if c['write'])
                    if defect in ('offset', 'base', 'register'):row['write'][defect] += 1
                    elif defect == 'index':row['write']['index'] += 1;row['write']['offset'] += row['write']['bytes']
                    elif defect == 'length':row['length'] += 1
                    elif defect == 'bits':row['length_source']['bits'] += 2;row['length'] += 1
                    else:row['write']['base'] = 4
                    try:check_fresh_fields(forged, audit, read)
                    except (AssertionError, KeyError):passed.append('fresh-forged-' + defect)
                    else:raise AssertionError('Forged fresh-write proof accepted: ' + defect)
            with (temp/'out.json.asm').open() as stream:check_fresh_stream(result, stream)
            if name=='saved-direct':
                for defect in ('class','source','scope','slot','store','suspension','register','frame','map','work','duplicate','missing-context'):
                    forged=copy.deepcopy(result);context=next(c for c in forged['saved_reference_contexts'] if c['observations']);ref=context['observations'][0]
                    if defect=='class':context['class_id']+=1
                    elif defect=='source':context['source_await']+=4
                    elif defect=='scope':context['scope']='unconditional'
                    elif defect=='slot':ref['slot']-=8
                    elif defect=='store':ref['store']+=4
                    elif defect=='suspension':ref['suspension']-=4
                    elif defect=='register':ref['register']=3
                    elif defect=='frame':forged['saved_reference_frames'][0]['points'].pop()
                    elif defect=='map':next(m for m in forged['saved_reference_stack_maps'] if m['site']==ref['suspension'])['objects'].remove(ref['slot'])
                    elif defect=='work':forged['saved_reference_work']['steps']+=1
                    elif defect=='duplicate':context['observations']*=2
                    else:forged['saved_reference_contexts'].remove(context)
                    try:check_saved_references(forged,audit,read)
                    except (AssertionError,KeyError):passed.append('saved-forged-'+defect)
                    else:raise AssertionError('Forged saved reference accepted: '+defect)
                lines=(temp/'out.json.asm').read_text().splitlines(keepends=True)
                for defect in ('scope','class','slot','site','missing','duplicate'):
                    forged=[]
                    for line in lines:
                        if '// async restored-reference:' in line:
                            if defect=='missing':continue
                            if defect=='duplicate':forged.append(line)
                            if defect=='scope':line=line.replace('conditional: ','')
                            if defect=='class':line=line.replace('heap class 0x2','heap class 0x7')
                            if defect=='slot':line=line.replace('FP-16','FP-24')
                            if defect=='site':line=line.replace('await 0x101c','await 0x1020')
                        forged.append(line)
                    try:check_saved_stream(result,forged)
                    except (AssertionError,KeyError):passed.append('saved-note-forged-'+defect)
                    else:raise AssertionError('Forged restored-reference comment accepted: '+defect)
            if name=='future-direct':
                for defect in ('class','conditions','producer','call','resume','origin','entry','frame','missing','duplicate','abi','body','work','value-alias'):
                    forged=copy.deepcopy(result);row=forged['await_future_bindings'][0];producer=forged['future_producers'][0]
                    if defect=='class':row['class_id']+=1
                    elif defect=='conditions':row['conditions']=[]
                    elif defect=='producer':row['producer']+=4
                    elif defect=='call':row['call']-=4
                    elif defect=='resume':row['resume_site']+=4
                    elif defect=='origin':row['source']['proof']=[0x1000]
                    elif defect=='entry':producer['entry']+=4
                    elif defect=='frame':producer['after_init'].clear()
                    elif defect=='missing':forged['await_future_bindings'].clear()
                    elif defect=='duplicate':forged['await_future_bindings']*=2
                    elif defect=='abi':forged['future_binding_abi']['suspend_state_offset']-=8
                    elif defect=='body':forged['future_binding_bodies'][0]['handlers']=[0x101c]
                    elif defect=='work':forged['future_binding_work']['steps']+=1
                    else:producer['class_id']+=1
                    try:check_future_bindings(forged,audit,read)
                    except (AssertionError,KeyError):passed.append('future-forged-'+defect)
                    else:raise AssertionError('Forged Future binding accepted: '+defect)
                lines=(temp/'out.json.asm').read_text().splitlines(keepends=True)
                for defect in ('unscoped','class','site','missing','duplicate'):
                    forged=[]
                    for line in lines:
                        if '// async delivered-value:' in line:
                            if defect=='missing':continue
                            if defect=='duplicate':forged.append(line)
                            if defect=='unscoped':line=line.replace('conditional: ','')
                            if defect=='class':line=line.replace('heap class 0x2','heap class 0x7')
                            if defect=='site':line=line.replace('await 0x101c','await 0x1018')
                        forged.append(line)
                    try:check_binding_stream(result,forged)
                    except (AssertionError,KeyError):passed.append('future-note-forged-'+defect)
                    else:raise AssertionError('Forged await note accepted: '+defect)
            def verify(value):
                from check_snapshot_annotations import decode_payload
                return check_receivers(value, read, lambda raw, address: decode_payload(decoder, raw, address), audit)
            if name == 'call-input-result-scope':
                for defect in ('class', 'site', 'proof', 'duplicate', 'binding'):
                    forged = copy.deepcopy(result)
                    c = next(v for v in forged['call_result_contexts'] if v['register_observations'])
                    row = next(v for v in c['register_observations'] if any(x['register'] == 'x1' for x in v['values']))
                    if defect == 'class': row['values'][0]['class_id'] += 1
                    elif defect == 'site': row['site'] += 4
                    elif defect == 'proof': row['values'][0]['proof'] = [0x900000]
                    elif defect == 'duplicate': c['register_observations'].append(copy.deepcopy(row))
                    else: c['return_bindings'][0]['callee'] += 4
                    try:
                        verify(forged)
                    except (AssertionError, KeyError):
                        passed.append('call-input-forged-'+defect)
                    else:
                        raise AssertionError('Forged register input was accepted: '+defect)
            if name == 'indirect-machine-result-in-register-context':
                for defect in ('missing', 'callee', 'class', 'proof', 'basis', 'duplicate'):
                    forged = copy.deepcopy(result)
                    context = next(c for c in forged['register_contexts'] if c['payload'] == 0x5000)
                    rows = context['certificate']['indirect_returns']
                    if defect == 'missing': rows.clear()
                    elif defect == 'callee': rows[0]['callee'] += 4
                    elif defect == 'class': rows[0]['class_id'] += 1
                    elif defect == 'proof': rows[0]['proof'].remove(rows[0]['site'])
                    elif defect == 'basis': rows[0]['basis'] = 'guessed'
                    else: rows *= 2
                    try:
                        verify(forged)
                    except (AssertionError, KeyError):
                        passed.append('indirect-result-tamper-'+defect)
                    else:
                        raise AssertionError('Accepted forged indirect result: '+defect)
            if name == 'sdk-stub-return-wrapper':
                for defect in ('summary-class', 'producer-basis', 'caller-basis', 'producer-site',
                               'phase-budget', 'missing-summary', 'ordinary-promotion', 'duplicate-producer'):
                    forged = copy.deepcopy(result)
                    if defect == 'summary-class':
                        forged['sdk_stub_return_summaries'][0][1] = 6
                    elif defect == 'producer-basis':
                        forged['sdk_stub_producer_contexts'][0]['return_bindings'][0]['basis'] = 'sdk_stub_summary'
                    elif defect == 'caller-basis':
                        forged['sdk_stub_caller_contexts'][0]['return_bindings'][0]['basis'] = 'machine_return_summary'
                    elif defect == 'producer-site':
                        forged['sdk_stub_producer_contexts'][0]['return_bindings'][0]['site'] += 4
                    elif defect == 'phase-budget':
                        forged['sdk_stub_result_analysis']['producers']['transfer_steps'] = 20000001
                    elif defect == 'missing-summary':
                        forged['sdk_stub_return_summaries'] = []
                    elif defect == 'ordinary-promotion':
                        forged['receiver_metadata']['machine_return_classes'].append([0x5000, 5])
                    else:
                        forged['sdk_stub_producer_contexts'] *= 2
                    try:
                        verify(forged)
                    except (AssertionError, KeyError):
                        passed.append('sdk-stub-tamper-'+defect)
                    else:
                        raise AssertionError('Accepted forged SDK result relation: '+defect)
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

        if args.closures_only:
            from closure_capture_cases import run_cases
            run_cases(run)
            print(f'{len(passed)} closure capture cases passed')
            return

        if args.joined_only:
            from joined_reference_cases import run_cases
            run_cases(run)
            print(f'{len(passed)} joined-reference cases passed')
            return

        if args.entry_reads_only:
            from callee_entry_cases import run_cases
            run_cases(run)
            print(f'{len(passed)} callee-entry read cases passed')
            return

        if args.contents_only:
            from fresh_content_cases import run_cases
            run_cases(run)
            print(f'{len(passed)} selected content cases passed')
            return
        if args.fresh_only:
            from fresh_field_cases import run_cases
            run_cases(run)
            print(f'{len(passed)} fresh initialization cases passed')
            return

        if args.captures_only:
            from captured_field_cases import run_cases
            run_cases(run)
            print(f'{len(passed)} captured field cases passed')
            return

        if args.field_inputs_only:
            from field_input_cases import run_cases
            run_cases(run)
            print(json.dumps(dict(status='PASSED',case_count=len(passed),cases=passed,memcheck=args.memcheck)))
            return

        if args.fields_only:
            from async_field_cases import run_cases
            run_cases(run)
            print(json.dumps(dict(status='PASSED',case_count=len(passed),cases=passed,memcheck=args.memcheck)))
            return

        if args.saved_only:
            from saved_reference_cases import run_cases
            run_cases(run)
            print(json.dumps(dict(status='PASSED',case_count=len(passed),cases=passed,memcheck=args.memcheck)))
            return

        if args.futures_only:
            from future_binding_cases import run_cases
            run_cases(run)
            print(json.dumps(dict(status='PASSED',case_count=len(passed),cases=passed,memcheck=args.memcheck)))
            return

        if args.completions_only:
            from completion_cases import run_cases
            run_cases(run)
            print(json.dumps(dict(status='PASSED',case_count=len(passed),cases=passed,memcheck=args.memcheck)))
            return

        if args.inputs_only:
            from input_origin_cases import run_cases as origin_cases
            from call_input_shape_cases import run_cases as shape_cases
            origin_cases(run);shape_cases(run)
            print(json.dumps(dict(status='PASSED',case_count=len(passed),cases=passed,memcheck=args.memcheck)))
            return

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
        for name, middle, expected in [('result', [], True), ('overwrite', ['mov x0, x2'], False),
                                        ('unknown-call', ['bl 0x5000'], False)]:
            d = run('sdk-stub-return-'+name, ['bl 0xf000'] + middle + native_dispatch,
                    {0xf000: ['svc #0', 'ret'], 0x5000: ['ret']}, sdk_stub_returns=True)
            assert bool([v for c in d['sdk_stub_producer_contexts'] for v in c['resolutions']]) == expected
            assert sum(e.get('sdk_stub_return') is not None for e in d['edges']) == 1
        d = run('sdk-stub-return-caller-spill-killed',
                prologue + ['ldr x0, [x27, #40]', 'stur x0, [x29, #-8]', 'bl 0xf000',
                            'ldur x0, [x29, #-8]'] + native_dispatch,
                {0xf000: ['svc #0', 'ret']}, sdk_stub_returns=True)
        assert not resolved(d)
        d = run('sdk-stub-return-wrapper', prologue + ['bl 0x5000'] + epilogue,
                {0x5000: prologue + ['bl 0xf000'] + epilogue, 0xf000: ['svc #0', 'ret']}, sdk_stub_returns=True)
        assert dict(d['sdk_stub_return_summaries']).get(0x5000) == 5
        recovered = run('sdk-stub-return-ldtr-producer', prologue + ['bl 0xf000', 'ldtr x8, [x8]'] + epilogue,
                        {0xf000: ['svc #0', 'ret']}, sdk_stub_returns=True)
        assert dict(recovered['sdk_stub_return_summaries']).get(0x1000) == 5
        recovered = run('sdk-stub-return-ldtr-caller', prologue + ['bl 0x5000', 'ldtr x8, [x8]'] + epilogue,
                        {0x5000: prologue + ['bl 0xf000'] + epilogue, 0xf000: ['svc #0', 'ret']}, sdk_stub_returns=True)
        assert any(c['payload'] == 0x1000 and c['normal_return_class'] == 5 for c in recovered['sdk_stub_caller_contexts'])
        baseline = run('sdk-stub-return-ordinary-baseline', prologue + ['bl 0x5000'] + epilogue,
                       {0x5000: prologue + ['bl 0xf000'] + epilogue, 0xf000: ['svc #0', 'ret']})
        for field in ('call_result_contexts', 'call_result_analysis', 'register_contexts', 'register_context_analysis',
                      'call_contexts', 'context_analysis', 'array_contexts', 'array_context_analysis'):
            assert d[field] == baseline[field], 'SDK work displaced ordinary analysis'
        exercise_register_contexts(run)
        from targeted_caller_cases import exercise_targeted_callers
        exercise_targeted_callers(run)
        async_stubs = {address: ['ret'] for address in (0x11000, 0x12000, 0x13000, 0x14000, 0x15000, 0x16000)}
        for name, body, expected in [
            ('await', ['bl 0x12000', 'ret'], [('await', 0x1004)]),
            ('await-with-unrelated-x1', ['mov x1, #7', 'bl 0x12000', 'ret'], [('await', 0x1008)]),
            ('typed-await', ['bl 0x13000', 'ret'], [('await_with_type_check', 0x1004)]),
            ('last-word-await', ['bl 0x12000'], [('await', None)]),
            ('complete-value', ['b 0x14000'], [('complete_value', None)]),
            ('complete-value-or-future', ['b 0x15000'], [('complete_value_or_future', None)]),
            ('init', ['bl 0x11000', 'ret'], [('init_async', None)]),
            ('interior-target', ['bl 0x12004', 'ret'], []),
            ('conditional-completion', ['cbz x0, 0x14000', 'ret'], []),
            ('jump-to-await', ['b 0x12000'], []),
            ('call-to-completion', ['bl 0x14000', 'ret'], []),
            ('multiple-awaits', ['bl 0x12000', 'bl 0x13000', 'ret'], [('await', 0x1004), ('await_with_type_check', 0x1008)]),
        ]:
            ordinary = run('async-baseline-'+name, body, async_stubs)
            described = run('async-boundary-'+name, body, async_stubs, async_contracts=True)
            assert [(v['operation'], v['resume_site']) for v in described['async_boundaries']] == expected
            assert len(described['async_contracts']) == 6
            assert not ordinary['call_input_origins']
            assert len(described['call_input_origins']) == sum(b['operation']!='init_async' for b in described['async_boundaries'])
            assert all(o['role'] in ('await_input','completion_operand') and o['register']==0 for o in described['call_input_origins'])
            assert {k:v for k,v in described.items() if k not in ('async_boundaries', 'async_contracts', 'async_inputs', 'completion_exception_contracts', 'completion_bodies', 'completion_summaries', 'completion_work', 'call_input_origins', 'input_origin_work')} == {
                k:v for k,v in ordinary.items() if k not in ('async_boundaries', 'async_contracts', 'async_inputs', 'completion_exception_contracts', 'completion_bodies', 'completion_summaries', 'completion_work', 'call_input_origins', 'input_origin_work')}, 'Async contracts changed ordinary analysis facts'
            text = (temp / 'out.json.asm').read_text()
            assert 'async resume entry:' in text
            if any(k.startswith('await') for k, _ in expected):
                assert 'input X0' in text and 'value origin unknown' in text and 'exception path separate' in text
        for name, body, kind, site, stop in [
            ('direct-producer', ['bl 0x4000', 'bl 0x12000', 'ret'], 'post_call_x0', 0x1000, 'matched'),
            ('register-copy', ['bl 0x4000', 'mov x8,x0', 'mov x0,x8', 'bl 0x12000', 'ret'], 'post_call_x0', 0x1000, 'matched'),
            ('local-spill', ['bl 0x4000', 'stur x0,[x29,#-8]', 'mov x0,#7', 'ldur x0,[x29,#-8]', 'bl 0x12000', 'ret'], 'post_call_x0', 0x1000, 'matched'),
            ('partial-spill', ['bl 0x4000', 'stur x0,[x29,#-8]', 'stur w1,[x29,#-8]', 'ldur x0,[x29,#-8]', 'bl 0x12000', 'ret'], 'load', 0x100c, 'partial_spill_write'),
            ('memory-call-barrier', ['bl 0x4000', 'stur x0,[x29,#-8]', 'bl 0x5000', 'ldur x0,[x29,#-8]', 'bl 0x12000', 'ret'], 'load', 0x100c, 'call_barrier'),
            ('alias-write', ['bl 0x4000', 'stur x0,[x29,#-8]', 'stur x1,[x8]', 'ldur x0,[x29,#-8]', 'bl 0x12000', 'ret'], 'load', 0x100c, 'possible_alias_write'),
            ('copied-register-clobber', ['bl 0x4000', 'mov x8,x0', 'bl 0x5000', 'mov x0,x8', 'bl 0x12000', 'ret'], None, None, 'call_barrier'),
            ('narrow-copy', ['bl 0x4000', 'mov w0,w1', 'bl 0x12000', 'ret'], None, None, 'narrow_definition'),
            ('computed-value', ['bl 0x4000', 'add x0,x0,#1', 'bl 0x12000', 'ret'], None, None, 'computed_definition'),
            ('earlier-delivery', ['bl 0x12000', 'bl 0x13000', 'ret'], 'await_delivery', 0x1000, 'matched'),
            ('completion-operand', ['bl 0x4000', 'b 0x15000'], 'post_call_x0', 0x1000, 'matched'),
            ('constructed-reference', ['bl 0x4000', 'mov x1,x0', 'add x0,x22,#0x30', 'stur w0,[x1,#7]', 'mov x0,x1', 'b 0x14000'], 'post_call_x0', 0x1000, 'matched'),
        ]:
            helpers = async_stubs | {0x4000: ['ret'], 0x5000: ['ret']}
            ordinary = run('async-origin-baseline-'+name, body, helpers)
            observed = run('async-origin-'+name, body, helpers, async_contracts=True)
            assert not ordinary['call_input_origins']
            assert all(o['role'] in ('await_input','completion_operand') and o['register']==0 for o in observed['call_input_origins'])
            row = observed['async_inputs'][-1]
            assert row['stop'] == stop and row['condition'] == 'normal_fallthrough'
            assert row['steps'] <= 64
            if kind is None:
                assert row['source'] is None
            else:
                assert row['source']['kind'] == kind and row['source']['site'] == site
                assert row['source']['proof'][0] == site and row['source']['proof'][-1] == row['site']
            assert {k:v for k,v in observed.items() if k not in ('async_boundaries','async_contracts','async_inputs','completion_exception_contracts','completion_bodies','completion_summaries','completion_work','call_input_origins','input_origin_work')} == {
                k:v for k,v in ordinary.items() if k not in ('async_boundaries','async_contracts','async_inputs','completion_exception_contracts','completion_bodies','completion_summaries','completion_work','call_input_origins','input_origin_work')}
        input_helpers = {0x4000: ['ldr x0, [x27, #40]', 'ret'], 0x3000: ['ret']}
        observed = run('call-input-result-scope', prologue + [
            'bl 0x4000', 'mov x1,x0', 'str x1,[x15]', 'bl 0x3000'] + epilogue, input_helpers)
        context = next(c for c in observed['call_result_contexts'] if c['register_observations'])
        observation = next(v for v in context['register_observations'] if any(x['register'] == 'x1' for x in v['values']))
        assert any(v['class_id'] == 1 for v in observation['values'])
        barrier = run('call-input-unknown-call-kills', prologue + [
            'bl 0x4000', 'mov x1,x0', 'str x1,[x15]', 'bl 0x3000', 'bl 0x3000'] + epilogue, input_helpers)
        context = next(c for c in barrier['call_result_contexts'] if c['register_observations'])
        sites = [v['site'] for v in context['register_observations'] if any(x['register'] == 'x1' for x in v['values'])]
        assert len(sites) == 1, 'An unknown call must not preserve the input class'
        for layout in ('old', 'new'):
            observed = run('stub-input-roles-' + layout, [
                'ldr x1,[x27,#40]', 'mov x2,#6', 'bl 0x11000',
                'ldr x1,[x27,#40]', 'ldr x2,[x27,#48]', 'ldr x3,[x27,#48]', 'bl 0x12000', 'ret'],
                {0x11000:['ret'], 0x12000:['ret']}, stub_inputs=layout)
            assert len(observed['stub_input_contracts']) == 2
            from stub_input_roles import input_records
            roles = [v for v in input_records(observed) if v['role']]
            assert any(v['role'] == 'array_length' and v['kind'] == 'word' and v['value'] == 6 for v in roles)
            assert any(v['role'] == 'closure_context' and v['register'] == ('x3' if layout == 'new' else 'x2') for v in roles)
            assert any(v['role'] == 'closure_length_flags' for v in roles) == (layout == 'new')
        unknown = run('stub-input-unknown-values', ['bl 0x11000', 'bl 0x12000', 'ret'],
                      {0x11000:['ret'], 0x12000:['ret']}, stub_inputs='new')
        from stub_input_roles import input_records
        assert all(v['kind'] == 'unknown' for v in input_records(unknown))
        from future_binding_cases import run_cases as run_future_cases
        run_future_cases(run)
        from saved_reference_cases import run_cases as run_saved_cases
        run_saved_cases(run)
        from async_field_cases import run_cases as run_field_cases
        run_field_cases(run)
        from fresh_field_cases import run_cases as run_fresh_cases
        run_fresh_cases(run)
        from closure_capture_cases import run_cases as run_closure_cases
        run_closure_cases(run)
        from joined_reference_cases import run_cases as run_joined_cases
        run_joined_cases(run)
        from callee_entry_cases import run_cases as run_entry_cases
        run_entry_cases(run)
        from fresh_content_cases import run_cases as run_content_cases
        run_content_cases(run)
        from captured_field_cases import run_cases as run_captured_cases
        run_captured_cases(run)
        from field_input_cases import run_cases as run_field_input_cases
        run_field_input_cases(run)
        from completion_cases import run_cases as run_completion_cases
        run_completion_cases(run)
        from input_origin_cases import run_cases as run_origin_cases
        run_origin_cases(run)
        from call_input_shape_cases import run_cases
        run_cases(run)
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
