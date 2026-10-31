"""Check inductive receiver CFG certificates against original instructions.

This checks every incoming edge against declared block invariants, rather than
rerunning the producer's fixed-point solver. SDK object classes are trusted
inputs cross-checked through the separate numerical VM audit.
"""
from collections import deque
import copy

import capstone as cs
from capstone import arm64 as a

from check_snapshot_annotations import branch, constant_move, integer_operation
from check_result_use import reads_result, transfer


UNKNOWN, WORD, RANGE, OBJECT, HEADER, POOL, DISPATCH, TARGET, STACK, THREAD, HEAP_ADDRESS = range(11)
EMPTY = (UNKNOWN, 0, 0, 0)
MASK64 = (1 << 64) - 1


def signed(value):
    return value - (1 << 64) if value >> 63 else value


def fact(kind, value=0, aux=0, origin=0):
    return kind, value & MASK64, aux & MASK64, origin


def reg(ins, number):
    name = ins.reg_name(number)
    if name in ('fp', 'lr'):
        return 29 if name == 'fp' else 30
    return int(name[1:]) if name.startswith(('x', 'w')) and name[1:].isdigit() else -1


def width(ins, number):
    name = ins.reg_name(number)
    return 32 if name.startswith('w') else 64 if name.startswith('x') or name in ('fp', 'lr') else 0


def read_reg(state, ins, number):
    if number in (a.ARM64_REG_XZR, a.ARM64_REG_WZR):
        return fact(WORD)
    index = reg(ins, number)
    if index < 0:
        return EMPTY
    value = state[index]
    if width(ins, number) == 32:
        if value[0] in (WORD, RANGE):
            return fact(value[0], value[1] & 0xffffffff if value[0] == WORD else min(value[1], 0xffffffff))
        if value[0] != HEADER:
            return fact(RANGE, 0xffffffff)
    return value


def supported_operand(state, ins, operand, bits):
    if operand.ext:
        return EMPTY
    if operand.type == a.ARM64_OP_IMM and operand.imm >= 0 and (not operand.shift.type or (operand.shift.type == a.ARM64_SFT_LSL and operand.shift.value == 12)):
        return fact(WORD, operand.imm << (12 if operand.shift.type else 0))
    if operand.type == a.ARM64_OP_REG and width(ins, operand.reg) == bits and (not operand.shift.type or (operand.shift.type == a.ARM64_SFT_LSL and operand.shift.value == 0)):
        return read_reg(state, ins, operand.reg)
    return EMPTY


def entails(producer, declared):
    if declared[0] == UNKNOWN:
        return True
    if declared[0] == RANGE and producer[0] in (RANGE, WORD):
        return producer[1] <= declared[1]
    return producer == declared


def memory_write(ins, operand):
    """Positive read-only load encodings; atomic operand flags are unreliable."""
    if operand.access & cs.CS_AC_WRITE:
        return True
    word = int.from_bytes(ins.bytes, 'little')
    if word & 0x3a000000 == 0x28000000:  # Integer/SIMD pair load/store.
        return not bool(word & (1 << 22))
    scalar = (word & 0x3b000000 == 0x39000000 or  # Unsigned immediate.
              word & 0x3b200000 == 0x38000000 or  # Unscaled/pre/post/unprivileged.
              word & 0x3b200c00 == 0x38200800)    # Register offset; excludes atomic RMW.
    if scalar:
        # SIMD opc=2 is a Q store; integer opc=2 is signed load/prefetch.
        return not bool(word & (1 << 22)) if word & (1 << 26) else ((word >> 22) & 3) == 0
    return True


def heap_field(base, operand, writeback, header, enabled):
    if writeback or operand.mem.index or base[0] not in ((OBJECT, HEAP_ADDRESS) if enabled else (OBJECT,)):
        return False
    offset = (signed(base[1]) if base[0] == HEAP_ADDRESS else 0) + operand.mem.disp
    return -(1 << 63) <= offset < 1 << 63 and offset >= header + 8


def check_receivers(graph, read, decode, audit):
    modern = graph.get('format', 4) >= 5
    spill_enabled = graph.get('format', 4) >= 7
    heap_address_enabled = graph.get('format', 4) >= 8
    claims = {e['site']: e['static_dispatch'] for e in graph['edges'] if e.get('static_dispatch') is not None}
    stack_claims = {e['site']: e['stack_inputs'] for e in graph['edges'] if e.get('stack_inputs')}
    load_claims = {(v['site'], v['register']): v for v in graph.get('entry_stack_loads', [])}
    array_claims = {e['site']: e['array_arguments'] for e in graph['edges'] if e.get('array_arguments')}
    assert len(array_claims) == sum(bool(e.get('array_arguments')) for e in graph['edges'])
    assert graph.get('format', 4) >= 13 or not array_claims
    indexed_claims = {e['site']: e['indexed_return'] for e in graph['edges'] if e.get('indexed_return') is not None}
    assert graph.get('format', 4) >= 14 or not indexed_claims
    assert len(indexed_claims) == sum(e.get('indexed_return') is not None for e in graph['edges'])
    return_claims = {e['site']: e['forwarded_return'] for e in graph['edges'] if e.get('forwarded_return') is not None}
    length_claims = {e['site']: e['array_length_return'] for e in graph['edges'] if e.get('array_length_return') is not None}
    assert graph.get('format', 4) >= 17 or not length_claims
    assert len(length_claims) == sum(e.get('array_length_return') is not None for e in graph['edges'])
    assert graph.get('format', 4) >= 12 or not return_claims and not any(c.get('forwarded_returns') for c in graph.get('call_contexts', []))
    assert len(return_claims) == sum(e.get('forwarded_return') is not None for e in graph['edges'])
    certificates = graph.get('receiver_certificates', [])
    contexts = graph.get('call_contexts', [])
    array_contexts = graph.get('array_contexts', [])
    path_contexts = graph.get('array_path_contexts', [])
    entry_traces = graph.get('array_entry_traces', [])
    result_traces = graph.get('array_result_traces', [])
    assert graph.get('format', 4) >= 20 or not result_traces
    assert graph.get('format', 4) >= 19 or not entry_traces
    assert all('array_input' not in c and 'path_condition' not in c and 'trace' not in c for c in contexts)
    assert all('path_condition' not in c for c in array_contexts)
    assert graph.get('format', 4) >= 18 or not path_contexts
    assert graph.get('format', 4) >= 6 or not contexts
    assert len(claims) == sum(e.get('static_dispatch') is not None for e in graph['edges'])
    assert len(stack_claims) == sum(bool(e.get('stack_inputs')) for e in graph['edges'])
    assert len(load_claims) == len(graph.get('entry_stack_loads', []))
    assert modern or not stack_claims and not load_claims
    assert len({c['payload'] for c in certificates}) == len(certificates)
    if not claims and not stack_claims and not load_claims and not return_claims and not length_claims and not array_claims and not indexed_claims and not contexts and not array_contexts and not path_contexts and not entry_traces and not result_traces and not graph.get('call_effects') and not graph.get('prefix_call_effects') and not graph.get('receiver_metadata', {}).get('nonreturning_calls'):
        assert not certificates
        return {'receiver_claims_checked': 0, 'receiver_incoming_edges_checked': 0}
    assert audit, 'Receiver checking requires the separate VM audit'
    metadata, profile = graph['receiver_metadata'], graph['profile']
    if graph.get('format', 4) >= 18:
        assert metadata['stack_limit_offset'] == audit.get('stack_limit_offset')
    assert 0 < metadata['class_id_bits'] <= 32 and metadata['class_id_shift'] + metadata['class_id_bits'] <= 32
    pools = dict(metadata['pool_classes'])
    pool_audit = dict(audit['pool_heap_classes'])
    allocations = dict(metadata['allocation_returns'])
    preserving_calls = dict(metadata.get('frame_preserving_calls', []))
    assert all(v in ('stack_overflow_without_fpu', 'array_write_barrier', 'double_to_integer') and (v != 'array_write_barrier' or heap_address_enabled) and (v != 'double_to_integer' or graph.get('format', 4) >= 9) and dict(audit.get('frame_preserving_calls', [])).get(k) == v
               for k, v in preserving_calls.items())
    thread_classes = dict(metadata.get('thread_heap_classes', []))
    assert modern or not thread_classes
    allocation_audit = dict(audit['class_allocations'])
    predefined_allocations = dict(audit.get('predefined_allocations', []))
    assert all(k not in allocation_audit or allocation_audit[k] == v for k, v in predefined_allocations.items())
    allocation_audit.update(predefined_allocations)
    preserved_registers = dict(metadata.get('preserved_call_registers', []))
    assert spill_enabled or not preserved_registers
    assert all(type(v) is int and 0 <= v < 1 << 31 and not v & ((1 << 15) | (1 << 29) | (1 << 30)) and
               dict(audit.get('preserved_call_registers', [])).get(k) == v for k, v in preserved_registers.items())
    assert all(not preserved_registers.get(k, 0) & (1 << 25) for k, v in preserving_calls.items() if v == 'array_write_barrier')
    assert all(pool_audit.get(k) == v for k, v in pools.items())
    assert all(allocation_audit.get(k) == v for k, v in allocations.items())
    assert all(dict(audit.get('thread_heap_classes', [])).get(k) == v for k, v in thread_classes.items())
    assert all(0 <= v < 1 << metadata['class_id_bits'] for v in thread_classes.values())
    from check_call_effects import check_call_effects, checked_nonreturning_calls
    nonreturning_calls = checked_nonreturning_calls(graph, audit)
    safe_callees, effect_instructions = check_call_effects(graph, read, decode, set(allocations) | set(preserving_calls), audit)
    prefix_certificates = graph.get('prefix_call_effects', [])
    assert graph.get('format', 4) >= 21 or not prefix_certificates
    assert len(prefix_certificates) <= 128
    prefix_nodes = {n['start']: n for n in graph['nodes']}
    for effect in prefix_certificates:
        assert effect.get('array_return') is not None or effect.get('array_length') is not None
        entry, parent = effect['payload'], effect.get('containing_payload', effect['payload'])
        assert type(entry) is int and type(parent) is int and parent in prefix_nodes
        assert 0 < prefix_nodes[parent]['end']-entry <= 256
    prefix_safe, prefix_instructions = check_call_effects(dict(graph, call_effects=prefix_certificates), read, decode, set(allocations) | set(preserving_calls), audit, allow_interior_entries=True)
    legacy_safe = safe_callees
    heap_bits = metadata.get('heap_bits_register')
    assert heap_bits is None or graph.get('format', 4) >= 13 and heap_bits == 'x28' and audit.get('heap_bits_register') == heap_bits
    array = metadata.get('array_body_contract', []) if graph.get('format', 4) >= 13 else []
    from check_array_elements import ArrayTrace
    verified_arrays = set()
    array_elements_checked = 0
    array_returns = {c['payload']: c['array_return'] for c in graph.get('call_effects', []) if c.get('array_return') is not None}
    verified_indexed = set()
    return_inputs = {c['payload']: c['return_input'] for c in graph.get('call_effects', []) if c.get('return_input') is not None}
    length_effects = {c['payload']: c['array_length'] for c in graph.get('call_effects', []) if c.get('array_length') is not None} if graph.get('format', 4) >= 17 else {}
    legacy_arrays, legacy_lengths = array_returns, length_effects
    prefix_arrays = {c['payload']: c['array_return'] for c in prefix_certificates if c.get('array_return') is not None}
    prefix_lengths = {c['payload']: c['array_length'] for c in prefix_certificates if c.get('array_length') is not None}
    verified_lengths, contextual_lengths = set(), 0
    nodes = {n['start']: n for n in graph['nodes']}
    dispatch = graph['dispatch_table']
    external = {n['address'] for node in nodes.values() for n in node['names']}
    external.update(v for v in dispatch['entries'] if v is not None)
    external.update(e['target'] for e in graph['edges'] if e['target'] is not None)
    image_start, image_end = min(nodes), max(n['end'] for n in nodes.values())
    assert {v for v in external if image_start <= v < image_end} == {v for v in metadata['entries'] if image_start <= v < image_end}
    verified, incoming_checks, blocks_checked = {}, 0, 0
    verified_stacks, verified_loads, verified_returns = set(), set(), set()
    context_return_count = 0
    context_results, context_callers, context_keys = 0, set(), set()
    from check_array_contexts import check_array_bindings
    array_context_callers = check_array_bindings(graph, stack_claims, array_claims, array, allocations)
    array_context_read_count, array_context_dispatch_count = 0, 0
    path_read_count, path_dispatch_count, path_length_count = 0, 0, 0
    entry_result_count, entry_length_count, entry_read_count, entry_dispatch_count = 0, 0, 0, 0
    result_use_count, result_indexed_count, result_length_count, result_read_count = 0, 0, 0, 0
    by_site = {e['site']: e for e in graph['edges']}
    checks = [(certificate, None) for certificate in certificates]
    for context in contexts:
        assert context['callers'] and len(set(context['callers'])) == len(context['callers'])
        assert not context_callers.intersection(context['callers'])
        context_callers.update(context['callers'])
        assert 0 < len(context['inputs']) <= 32
        bindings = {}
        for item in context['inputs']:
            offset, kind, value = item['sp_offset'], item['kind'], int(item['value'], 16)
            assert type(offset) is int and 0 <= offset < 256 and offset % 8 == 0 and offset not in bindings
            assert kind in ('word', 'heap_class') and 0 <= value <= MASK64
            assert kind != 'heap_class' or value < 1 << metadata['class_id_bits']
            bindings[offset] = fact(WORD if kind == 'word' else OBJECT, value)
        key = context['payload'], tuple(sorted(bindings.items()))
        assert key not in context_keys
        context_keys.add(key)
        for site in context['callers']:
            caller = by_site[site]
            assert caller['kind'] == 'call' and caller['target'] == context['payload'] and site in stack_claims
            supplied = {v['sp_offset']: fact(WORD if v['kind'] == 'word' else OBJECT, int(v['value'], 16)) for v in stack_claims[site]}
            assert all(supplied.get(k) == v for k, v in bindings.items())
        assert context['certificate']['payload'] == context['payload'] and context['payload'] in nodes
        assert context['resolutions'] or context.get('forwarded_returns') or context.get('array_length_returns')
        assert len({r['site'] for r in context['resolutions']}) == len(context['resolutions'])
        assert len({r['site'] for r in context.get('forwarded_returns', [])}) == len(context.get('forwarded_returns', []))
        checks.append((context['certificate'], context))

    checks.extend((c['certificate'], c) for c in array_contexts + path_contexts + entry_traces + result_traces if c['certificate'] is not None)

    for certificate, context in checks:
        array_mode = context is not None and 'array_input' in context
        path = context.get('path_condition') if context else None
        trace = context.get('trace') if context else None
        safe_callees = legacy_safe | prefix_safe if trace else legacy_safe
        array_returns = legacy_arrays | prefix_arrays if trace else legacy_arrays
        length_effects = legacy_lengths | prefix_lengths if trace else legacy_lengths
        use_mode = bool(context and context.get('scope') == 'entry_result_use')
        assert not trace or context['scope'] in ('entry_prefix', 'entry_result_use')
        result_origin, result_dependencies = None, 0
        trace_guards = {}
        active_indexed = {v['site']: v for v in context['indexed_returns']} if trace else indexed_claims
        verified_trace_indexed = set()
        if array_mode and path is None:
            uses_continuation = any(b.get('array_continuation') is not None for b in certificate['blocks'])
            assert context['scope'] == ('entry_chain' if uses_continuation else 'entry_block')
        active_array_reads = {v['site']: v for v in context['array_reads']} if array_mode else {}
        verified_array_reads = set()
        active_claims = {r['site']: r for r in context['resolutions']} if context else claims
        active_stacks, active_loads = ({}, {}) if context else (stack_claims, load_claims)
        verified_context = set()
        active_returns = {r['site']: r for r in context.get('forwarded_returns', [])} if context else return_claims
        verified_context_returns = set()
        active_lengths = {v['site']: v for v in context.get('array_length_returns', [])} if context else length_claims
        assert not context or len(active_lengths) == len(context.get('array_length_returns', []))
        assert graph.get('format', 4) >= 17 or not active_lengths
        verified_context_lengths = set()
        input_values = {v['sp_offset']: fact(WORD if v['kind'] == 'word' else OBJECT, int(v['value'], 16))
                        for v in context['inputs']} if context else {}
        start = certificate['payload']
        node = nodes[start]
        instructions = decode(read(start, node['end'] - start), start)
        if path is not None:
            from check_stack_checks import check_initial_stack_check
            path = check_initial_stack_check(context, instructions, graph, audit, external)
        if trace:
            assert set(trace) == {'blocks', 'stop', 'stack_checks'} | ({'getter'} if use_mode else set())
            assert 1 <= len(trace['blocks']) <= 64 and len(set(trace['blocks'])) == len(trace['blocks'])
            assert trace['blocks'][0] == start and all(type(pc) is int for pc in trace['blocks'])
            assert type(trace['stop']) is int and len(trace['stack_checks']) <= 8
            if use_mode:
                assert type(trace['getter']) is int and trace['getter'] != trace['stop']
                assert set(active_indexed) == {trace['getter']} and set(active_claims) == {trace['stop']}
            else:
                assert trace['stop'] in active_indexed
            for guard in trace['stack_checks']:
                check_initial_stack_check(context, instructions, graph, audit, external, guard)
                assert guard['site'] not in trace_guards and guard['site'] != path['site']
                trace_guards[guard['site']] = guard
        by_address = {ins.address: ins for ins in instructions}
        successors = {}
        leaders = {start}
        targeted = set(external)
        writes = {}
        for ins in instructions:
            # The architectural CMP/CMN/TST destination is discarded. Ignore
            # Capstone's erroneous operand-write flag on their first source.
            written = ins.regs_write if ins.id in (a.ARM64_INS_CMP, a.ARM64_INS_CMN, a.ARM64_INS_TST, a.ARM64_INS_CCMP, a.ARM64_INS_CCMN) else ins.regs_access()[1]
            writes[ins.address] = {reg(ins, r) for r in written} - {-1}
            result = branch(int.from_bytes(ins.bytes, 'little'), ins.address)
            if result:
                kind, target = result
                if isinstance(target, int):
                    targeted.add(target)
                assert kind != 'indirect_jump', 'Unknown indirect jump invalidates CFG inference'
                if isinstance(target, int) and start <= target < node['end']:
                    leaders.add(target)
            if result or ins.group(cs.CS_GRP_RET) or ins.id in (a.ARM64_INS_BRK, a.ARM64_INS_HLT):
                if ins.address + 4 < node['end']:
                    leaders.add(ins.address + 4)
            if ins.address in external:
                leaders.add(ins.address)
        if array_mode:
            for ins in instructions:
                result = branch(int.from_bytes(ins.bytes, 'little'), ins.address)
                assert not (result and result[0] not in ('call', 'indirect_call') and result[1] == start), 'Entry backedge can recreate input contents'
        boundaries = sorted(leaders) + [node['end']]
        blocks = certificate['blocks']
        assert [(b['start'], b['end']) for b in blocks] == list(zip(boundaries, boundaries[1:]))
        assert len(blocks) <= 1024 and len(instructions) <= 16384
        trace_next = {}
        if trace:
            block_map = {b['start']: b for b in blocks}
            assert set(trace['blocks']) == {b['start'] for b in blocks if b['reachable']}
            assert sum((block_map[pc]['end']-pc)//4 for pc in trace['blocks']) <= 256
            assert block_map[trace['blocks'][-1]]['end']-4 == trace['stop']
            assert all(pc in {block_map[b]['end']-4 for b in trace['blocks']} for pc in trace_guards)
            trace_next = {block_map[pc]['end']-4: nxt for pc, nxt in zip(trace['blocks'], trace['blocks'][1:])}

        all_writes = set().union(*writes.values())
        seed = [EMPTY] * 31
        seed[15] = fact(STACK)
        seed[29] = fact(STACK, aux=1 if modern else 0)
        roots = [(profile['pool_register'], POOL, 0), (profile.get('dispatch_register'), DISPATCH, 0), (metadata['null_register'], OBJECT, metadata['null_class_id'])]
        if modern:
            roots.append((profile.get('thread_register'), THREAD, 0))
        for name, kind, value in roots:
            if name and name.startswith('x') and int(name[1:]) not in all_writes:
                seed[int(name[1:])] = fact(kind, value)
        seed = tuple(seed)

        def forwarded_at(state, live, spills, ins):
            if metadata.get('word_return_register') != 'x0':
                return None
            ops = ins.operands
            if len(ops) != 1:
                return None
            target = None
            if ins.id == a.ARM64_INS_BL and ops[0].type == a.ARM64_OP_IMM:
                target = ops[0].imm
            elif ins.id == a.ARM64_INS_BLR and ops[0].type == a.ARM64_OP_REG:
                loaded = read_reg(state, ins, ops[0].reg)
                if loaded[0] == TARGET and loaded[1] < len(dispatch['entries']):
                    target = dispatch['entries'][loaded[1]]
            if target not in return_inputs or target not in safe_callees:
                return None
            sp = state[15]
            if sp[0] != STACK or sp[2] != 0 or signed(sp[1]) > -16 or any(v[0] == STACK for r, v in enumerate(state) if r not in (15, 29)):
                return None
            offset = signed(sp[1]) + return_inputs[target]
            value = input_values.get(offset, EMPTY) if offset >= 0 and offset in live else fact(OBJECT, spills[offset]) if offset in spills else EMPTY
            if value[0] == OBJECT:
                return target, return_inputs[target], value[1]
            return None

        def indexed_at(state, ins, contents):
            if metadata.get('word_return_register') != 'x0' or contents.seed is None or contents.input_binding != bool(trace) or len(ins.operands) != 1:
                return None
            op = ins.operands[0]
            target = op.imm if ins.id == a.ARM64_INS_BL and op.type == a.ARM64_OP_IMM else None
            if ins.id == a.ARM64_INS_BLR and op.type == a.ARM64_OP_REG:
                value = read_reg(state, ins, op.reg)
                if value[0] == TARGET and value[1] < len(dispatch['entries']):
                    target = dispatch['entries'][value[1]]
            if target not in array_returns or target not in safe_callees:
                return None
            sp = state[15]
            if sp[0] != STACK or sp[2] or signed(sp[1]) > -16 or any(v[0] == STACK for r, v in enumerate(state) if r not in (15, 29)):
                return None
            relation = array_returns[target]
            if signed(sp[1])+relation['array_sp_offset'] not in contents.roots:
                return None
            index = contents.words.get(signed(sp[1])+relation['index_sp_offset'])
            if index is None or index > 62 or index % 2 or index//2 >= contents.seed[1]:
                return None
            cid = contents.cells.get(array[2]+index//2*array[3])
            return (target, contents.seed[0], index//2, cid) if cid is not None else None

        continued_arrays = {}

        def length_at(state, ins, contents):
            if not array or metadata.get('word_return_register') != 'x0' or contents.seed is None or len(ins.operands) != 1:
                return None
            layout = metadata.get('array_length_layout', [])
            if not layout or layout[0] != allocations[array[0]] or layout[2] != array[3] or layout[3] != 1 or contents.seed[1] > 32:
                return None
            op = ins.operands[0]
            target = op.imm if ins.id == a.ARM64_INS_BL and op.type == a.ARM64_OP_IMM else None
            if ins.id == a.ARM64_INS_BLR and op.type == a.ARM64_OP_REG:
                value = read_reg(state, ins, op.reg)
                if value[0] == TARGET and value[1] < len(dispatch['entries']):
                    target = dispatch['entries'][value[1]]
            if target not in safe_callees or target not in length_effects:
                return None
            effect, sp = length_effects[target], state[15]
            if sp[0] != STACK or sp[2] != 0 or signed(sp[1]) > -16 or any(v[0] == STACK for r, v in enumerate(state) if r not in (15, 29)):
                return None
            if signed(sp[1])+effect['array_sp_offset'] not in contents.roots:
                return None
            return (target, effect['array_sp_offset'], contents.seed[1], None if contents.input_binding else contents.seed[0],
                    contents.input_offset if contents.input_binding else None, effect['written_registers'])

        def step(state, comparison, live, spills, ins, contents):
            nonlocal result_origin, result_dependencies
            dependent = use_mode and reads_result(ins, result_dependencies, reg)
            old_origin = result_origin
            if use_mode and old_origin is not None and ins.group(cs.CS_GRP_CALL):
                assert ins.address == trace['stop'] and ins.id == a.ARM64_INS_BLR
                source = reg(ins, ins.operands[0].reg)
                assert source >= 0 and state[source][0] == TARGET and result_dependencies & (1 << source), 'Target is unrelated to getter value'
            fresh = None
            indexed = indexed_at(state, ins, contents)
            length_return = length_at(state, ins, contents)
            continuation = copy.deepcopy(contents) if length_return and ins.address+4 < node['end'] and (trace or ins.address+4 not in targeted) else None
            element = contents.result(ins)
            length = state[array[1]] if array else EMPTY
            forwarded = forwarded_at(state, live, spills, ins)
            old = state
            state = list(state)
            live = set(live)
            spills = dict(spills)
            ops = ins.operands
            destination = reg(ins, ops[0].reg) if ops and ops[0].type == a.ARM64_OP_REG else -1
            indirect_callee = None
            if graph.get('format', 4) >= 10 and ins.id == a.ARM64_INS_BLR and len(ops) == 1 and ops[0].type == a.ARM64_OP_REG:
                indirect = read_reg(old, ins, ops[0].reg)
                if indirect[0] == TARGET and indirect[1] < len(dispatch['entries']) and dispatch['entries'][indirect[1]] in safe_callees:
                    indirect_callee = dispatch['entries'][indirect[1]]
            bits = width(ins, ops[0].reg) if destination >= 0 else 0
            produced = EMPTY
            if ins.id in (a.ARM64_INS_DC, a.ARM64_INS_SYS, a.ARM64_INS_SYSL):
                state = [EMPTY if f[0] in (OBJECT, HEADER, HEAP_ADDRESS) else f for f in state]
                live.clear()
                spills.clear()
            def concrete(number, size):
                if number == 31: return 0
                return old[number][1] & ((1 << size)-1) if old[number][0] == WORD else None
            signed_value = None
            if trace and ins.id in (a.ARM64_INS_SBFX, a.ARM64_INS_SBFIZ):
                from check_entry_trace import signed_field
                signed_value = signed_field(int.from_bytes(ins.bytes, 'little'), concrete)
            word = int.from_bytes(ins.bytes, 'little')
            move = constant_move(word)
            operation = integer_operation(word)
            if move and destination >= 0:
                kind, number, size, value = move
                assert number == destination
                if kind == 'literal':
                    produced = fact(WORD, value)
                elif kind == 'copy':
                    produced = read_reg(old, ins, ops[1].reg)
                elif kind == 'keep' and old[destination][0] == WORD:
                    produced = fact(WORD, ((old[destination][1] & ~value[1]) | value[0]) & ((1 << size) - 1))
            elif operation and destination >= 0 and (
                ins.id == a.ARM64_INS_UBFX and len(ops) == 4 or
                ins.id in (a.ARM64_INS_ADD, a.ARM64_INS_SUB) and len(ops) == 3):
                kind, number, size, value = operation
                if kind == 'extract':
                    source = read_reg(old, ins, ops[1].reg)
                    lsb, length = value[1:]
                    if length <= 32:
                        produced = fact(RANGE, (1 << length) - 1)
                        if source[0] == WORD:
                            produced = fact(WORD, (source[1] >> lsb) & ((1 << length) - 1))
                        elif source[0] == HEADER and (lsb, length) == (metadata['class_id_shift'], metadata['class_id_bits']):
                            produced = fact(WORD, source[1])
                else:
                    left = read_reg(old, ins, ops[1].reg)
                    right = supported_operand(old, ins, ops[2], size)
                    if right[0] == WORD:
                        if left[0] == WORD:
                            produced = fact(WORD, (left[1] + right[1] if kind == 'add' else left[1] - right[1]) & ((1 << size) - 1))
                        elif heap_address_enabled and size == 64 and left[0] in (OBJECT, HEAP_ADDRESS):
                            value = (signed(left[1]) if left[0] == HEAP_ADDRESS else 0) + (signed(right[1]) if kind == 'add' else -signed(right[1]))
                            if -(1 << 20) <= value <= 1 << 20:
                                cid = left[1] if left[0] == OBJECT else left[2]
                                produced = fact(HEAP_ADDRESS, value, cid) if value else fact(OBJECT, cid)
                        elif size == 64 and left[0] in (POOL, DISPATCH, STACK, THREAD):
                            value = signed(left[1]) + (signed(right[1]) if kind == 'add' else -signed(right[1]))
                            if -(1 << 63) <= value < 1 << 63 and (left[0] != STACK or -(1 << 20) <= value <= 1 << 20):
                                produced = fact(left[0], value, left[2] if modern else 0)
            if ins.id in (a.ARM64_INS_LDR, a.ARM64_INS_LDUR) and len(ops) == 2 and ops[1].type == a.ARM64_OP_MEM and not ins.writeback:
                op = ops[1]
                base = read_reg(old, ins, op.mem.base)
                if not op.mem.index:
                    if base[0] == POOL and bits == 64:
                        relative = signed(base[1]) + op.mem.disp - profile['pool_data_offset']
                        if relative >= 0 and relative % profile['pool_slot_size'] == 0 and relative // profile['pool_slot_size'] in pools:
                            produced = fact(OBJECT, pools[relative // profile['pool_slot_size']])
                    elif base[0] == THREAD and bits == 64 and signed(base[1]) + op.mem.disp in thread_classes:
                        produced = fact(OBJECT, thread_classes[signed(base[1]) + op.mem.disp])
                    elif base[0] == STACK and base[2] == 0 and signed(base[1]) + op.mem.disp in live:
                        value = input_values[signed(base[1]) + op.mem.disp]
                        if bits == 64:
                            produced = value
                        elif bits == 32 and value[0] == WORD:
                            produced = fact(WORD, value[1] & 0xffffffff)
                    elif spill_enabled and base[0] == STACK and base[2] == 0 and bits == 64 and signed(base[1]) + op.mem.disp in spills:
                        produced = fact(OBJECT, spills[signed(base[1]) + op.mem.disp])
                    elif base[0] == OBJECT and op.mem.disp == metadata['header_displacement'] and bits in (32, 64):
                        produced = fact(HEADER, base[1])
                elif base[0] == DISPATCH and bits == width(ins, op.mem.index) == 64 and not op.ext and op.shift.type == a.ARM64_SFT_LSL and op.shift.value == 3:
                    index = read_reg(old, ins, op.mem.index)
                    offset = signed(base[1]) + op.mem.disp
                    if index[0] == WORD and offset % 8 == 0 and -(1 << 63) <= offset < 1 << 63:
                        slot = dispatch['origin'] + offset // 8 + signed(index[1])
                        if 0 <= slot < len(dispatch['entries']) and dispatch['entries'][slot] is not None:
                            produced = fact(TARGET, slot, index[1], ins.address)
            stack_writeback = None
            for n, op in enumerate(ops):
                if op.type == a.ARM64_OP_MEM and ins.writeback:
                    base = read_reg(old, ins, op.mem.base)
                    number = reg(ins, op.mem.base)
                    if base[0] == STACK and not op.mem.index and number >= 0 and number != destination:
                        delta = op.mem.disp if n + 1 == len(ops) else ops[n + 1].imm if n + 2 == len(ops) and ops[n + 1].type == a.ARM64_OP_IMM else None
                        if delta is not None and -(1 << 20) <= signed(base[1]) + delta <= 1 << 20:
                            stack_writeback = number, fact(STACK, signed(base[1]) + delta, base[2] if modern else 0)
            for op in ops:
                if op.type == a.ARM64_OP_MEM and memory_write(ins, op):
                    base = read_reg(old, ins, op.mem.base)
                    stack = base[0] == STACK
                    field = heap_field(base, op, ins.writeback, metadata['header_displacement'], heap_address_enabled)
                    if not stack and not field:
                        state = [EMPTY if f[0] in (OBJECT, HEADER, HEAP_ADDRESS) else f for f in state]
                    if not field:
                        size = 1 if ins.id in (a.ARM64_INS_STRB, a.ARM64_INS_STURB) else 2 if ins.id in (a.ARM64_INS_STRH, a.ARM64_INS_STURH) else 0
                        if ins.id in (a.ARM64_INS_STR, a.ARM64_INS_STUR, a.ARM64_INS_STP) and ops[0].type == a.ARM64_OP_REG:
                            size = width(ins, ops[0].reg) // 8 * (2 if ins.id == a.ARM64_INS_STP else 1)
                        offset = signed(base[1]) + op.mem.disp
                        if not stack or base[2] != 0 or op.mem.index or not size or not -(1 << 63) <= offset <= (1 << 63) - 1 - size:
                            live.clear()
                            spills.clear()
                        else:
                            live.difference_update(k for k in tuple(live) if offset < k + 8 and k < offset + size)
                            spills = {k: v for k, v in spills.items() if not (offset < k + 8 and k < offset + size)}
                        sp = old[15]
                        pair = ins.id == a.ARM64_INS_STP
                        full_store = spill_enabled and ins.id in (a.ARM64_INS_STR, a.ARM64_INS_STUR, a.ARM64_INS_STP) and not ins.writeback and stack and base[2] == 0 and not op.mem.index and sp[0] == STACK and sp[2] == 0
                        full_store = full_store and all(v.type == a.ARM64_OP_REG and width(ins, v.reg) == 64 for v in ops[:2 if pair else 1])
                        if full_store:
                            for part in range(2 if pair else 1):
                                at = offset + part * 8
                                if not signed(sp[1]) <= at < 0 or at % 8:
                                    continue
                                value = read_reg(old, ins, ops[part].reg)
                                if value[0] == OBJECT:
                                    if len(spills) >= 64:
                                        spills.clear()
                                    spills[at] = value[1]
            if element is not None:
                produced = fact(OBJECT, element)
            contents.step(old, ins, writes[ins.address], memory_write)
            if ins.update_flags or ins.id == a.ARM64_INS_MSR or a.ARM64_REG_NZCV in ins.regs_write or (comparison and comparison[0] in writes[ins.address]):
                comparison = ()
            if signed_value is not None: produced = fact(WORD, signed_value)
            for number in writes[ins.address]:
                state[number] = EMPTY
            if destination >= 0 and destination in writes[ins.address]:
                if produced[0] == UNKNOWN and bits == 32:
                    produced = fact(RANGE, 0xffffffff)
                state[destination] = produced
            if stack_writeback:
                state[stack_writeback[0]] = stack_writeback[1]
            if ins.id == a.ARM64_INS_CMP and len(ops) == 2 and destination >= 0:
                right = supported_operand(state, ins, ops[1], bits)
                if right[0] == WORD:
                    comparison = (destination, bits, right[1] & ((1 << bits) - 1), ins.address)
            if ins.group(cs.CS_GRP_CALL) or ins.group(cs.CS_GRP_INT):
                sp, fp = state[15], state[29]
                preserves = (indirect_callee is not None or ins.id == a.ARM64_INS_BL and len(ops) == 1 and ops[0].type == a.ARM64_OP_IMM and (
                    ops[0].imm in allocations or ops[0].imm in preserving_calls or ops[0].imm in safe_callees)) and sp[0] == STACK and sp[2] == 0 and signed(sp[1]) <= -16
                preserves = preserves and not any(value[0] == STACK for r, value in enumerate(state) if r not in (15, 29))
                if not preserves:
                    live.clear()
                    spills.clear()
                before = tuple(state)
                state, comparison = list(seed), ()
                if modern:
                    state[15] = sp if ins.group(cs.CS_GRP_CALL) and sp[0] == STACK else EMPTY
                    state[29] = fp if ins.group(cs.CS_GRP_CALL) and fp[0] == STACK else EMPTY
                if ins.id == a.ARM64_INS_BL:
                    mask = preserved_registers.get(ops[0].imm, 0)
                    for r in range(31):
                        if mask & (1 << r):
                            if before[r][0] != HEAP_ADDRESS or preserving_calls.get(ops[0].imm) == 'array_write_barrier':
                                state[r] = before[r]
                if ins.id == a.ARM64_INS_BL and ops[0].imm in allocations:
                    state[int(metadata['allocation_result_register'][1:])] = fact(OBJECT, allocations[ops[0].imm])
                if forwarded and preserves:
                    state[0] = fact(OBJECT, forwarded[2])
                if indexed and preserves:
                    state[0] = fact(OBJECT, indexed[3])
                if length_return and preserves:
                    mask = length_return[5] | (1 << 30)
                    for r in range(31):
                        if not mask & (1 << r):
                            state[r] = before[r]
                    state[0] = fact(WORD, length_return[2] << 1)
                    if continuation is not None:
                        continuation.continue_length_call(mask)
                        continued_arrays[ins.address+4] = ins.address, continuation
            if array and ins.id == a.ARM64_INS_BL and len(ops) == 1 and ops[0].type == a.ARM64_OP_IMM and ops[0].imm == array[0] and length[0] == WORD and length[1] <= 64 and length[1] % 2 == 0:
                fresh = (ins.address, length[1] // 2)
            sp = state[15]
            spills = {k: v for k, v in spills.items() if sp[0] == STACK and sp[2] == 0 and k >= signed(sp[1])}
            if use_mode:
                result_dependencies = transfer(result_dependencies, writes[ins.address], destination, produced[0] != UNKNOWN, dependent, state)
                if ins.group(cs.CS_GRP_CALL) or ins.group(cs.CS_GRP_INT):
                    result_dependencies = 0
                    if indexed and preserves:
                        assert old_origin is None and ins.address == trace['getter']
                        result_origin, result_dependencies = ins.address, 1
                        live.clear(); spills.clear()
            if (path and ins.address == path['site']) or (trace and ins.address in trace_next and not ins.group(cs.CS_GRP_CALL)):
                continued = copy.deepcopy(contents)
                continued.continue_length_call(0)
                continued_arrays[trace_next[ins.address] if trace else path['successor']] = ins.address, continued
            return tuple(state), comparison, frozenset(live), spills, fresh

        def outgoing(block, state, comparison, live, spills, fresh):
            last = by_address[block['end'] - 4]
            result = branch(int.from_bytes(last.bytes, 'little'), last.address)
            if trace and last.address == trace['stop']:
                return []
            if trace and last.address in trace_guards:
                return [(trace_guards[last.address]['successor'], state, comparison, live, spills, fresh)]
            if path and last.address == path['site']:
                return [(path['successor'], state, comparison, live, spills, fresh)]
            if last.group(cs.CS_GRP_RET) or last.id in (a.ARM64_INS_BRK, a.ARM64_INS_HLT):
                return []
            if result and result[0] == 'call' and result[1] in nonreturning_calls:
                return []
            if not result or result[0] in ('call', 'indirect_call'):
                return [(block['end'], state, comparison, live, spills, fresh)] if block['end'] < node['end'] else []
            kind, target = result
            if kind == 'jump':
                return [(target, state, comparison, live, spills, fresh)] if start <= target < node['end'] else []
            compared, bits, equal_value, equality_taken, known = -1, 0, 0, False, None
            if trace and last.address-4 >= block['start']:
                from check_entry_trace import branch_condition
                def concrete(number, size):
                    return state[number][1] & ((1 << size)-1) if number < 31 and state[number][0] == WORD else None
                known = branch_condition(int.from_bytes(last.bytes, 'little'), int.from_bytes(by_address[last.address-4].bytes, 'little'), concrete)

            if last.id == a.ARM64_INS_B and last.cc in (a.ARM64_CC_EQ, a.ARM64_CC_NE) and comparison:
                compared, bits, equal_value, _ = comparison
                equality_taken = last.cc == a.ARM64_CC_EQ
            elif last.id in (a.ARM64_INS_CBZ, a.ARM64_INS_CBNZ):
                compared, bits = reg(last, last.operands[0].reg), width(last, last.operands[0].reg)
                equality_taken = last.id == a.ARM64_INS_CBZ
            elif last.id in (a.ARM64_INS_TBZ, a.ARM64_INS_TBNZ):
                value = read_reg(state, last, last.operands[0].reg)
                bit = last.operands[1].imm
                if value[0] == WORD:
                    known = (((value[1] >> bit) & 1) == 0) == (last.id == a.ARM64_INS_TBZ)
                elif bit == 0 and reg(last, last.operands[0].reg) >= 0 and state[reg(last, last.operands[0].reg)][0] == OBJECT:
                    known = last.id == a.ARM64_INS_TBNZ
            if compared >= 0:
                value = state[compared]
                if value[0] == WORD:
                    known = ((value[1] & ((1 << bits) - 1)) == equal_value) == equality_taken
                elif value[0] == RANGE and equal_value > value[1]:
                    known = not equality_taken
            results = []
            if trace:
                assert known is not None, 'Unknown conditional prefix edge'
            for taken in (False, True):
                if known is not None and known != taken:
                    continue
                address = target if taken else last.address + 4
                if not start <= address < node['end']:
                    continue
                edge_state = list(state)
                if compared >= 0 and taken == equality_taken:
                    old = state[compared]
                    if bits == 64 or old[0] in (WORD, RANGE) and old[1] <= 0xffffffff:
                        edge_state[compared] = fact(WORD, equal_value)
                results.append((address, tuple(edge_state), comparison, live, spills, fresh))
            return results

        declared, compares, outgoing_edges, inputs, declared_live, declared_spills, declared_fresh = {}, {}, {}, {}, {}, {}, {}
        ordered_blocks = ([block_map[pc] for pc in trace['blocks']] + [b for b in blocks if b['start'] not in trace['blocks']]) if trace else blocks
        for block in ordered_blocks:
            assert block['entry'] == (block['start'] == start or not context and block['start'] in external)
            fresh = block.get('fresh_array')
            assert graph.get('format', 4) >= 13 or fresh is None
            if fresh is not None:
                assert array and type(fresh['allocation']) is int and fresh['allocation'] in by_address and type(fresh['length']) is int and 0 <= fresh['length'] <= 32
            declared_fresh[block['start']] = (fresh['allocation'], fresh['length']) if fresh is not None else None
            live_inputs = block.get('live_inputs', [])
            assert len(set(live_inputs)) == len(live_inputs) and set(live_inputs) <= input_values.keys()
            declared_live[block['start']] = frozenset(live_inputs)
            cells = block.get('spills', [])
            assert spill_enabled or not cells
            assert len(cells) <= 64 and len(dict(cells)) == len(cells)
            assert all(type(k) is int and -(1 << 20) <= k < 0 and k % 8 == 0 and type(v) is int and 0 <= v < 1 << metadata['class_id_bits'] for k, v in cells)
            declared_spills[block['start']] = dict(cells)
            values = [EMPTY] * 31
            seen = set()
            for number, kind, value, aux, origin in block['facts']:
                assert 0 <= number < 31 and number not in seen and UNKNOWN < kind <= (HEAP_ADDRESS if heap_address_enabled else THREAD if modern else STACK)
                seen.add(number)
                parts = [int(v, 16) for v in (value, aux, origin)]
                assert all(0 <= v <= MASK64 for v in parts)
                if kind == HEAP_ADDRESS:
                    assert heap_address_enabled and 0 < abs(signed(parts[0])) <= 1 << 20 and parts[1] < 1 << metadata['class_id_bits'] and parts[2] == 0
                else:
                    assert kind == TARGET or (modern and kind == STACK and parts[1] <= 3 and parts[2] == 0) or parts[1:] == [0, 0]
                values[number] = fact(kind, *parts)
            declared[block['start']] = tuple(values)
            compares[block['start']] = tuple(block['compare'])
            assert not compares[block['start']] or len(compares[block['start']]) == 4
            if compares[block['start']]:
                number, bits, value, site = compares[block['start']]
                assert 0 <= number < 31 and bits in (32, 64) and 0 <= value < 1 << bits and site in by_address
            if block['entry']:
                entry = list(seed)
                if modern and block['start'] != start:
                    entry[15], entry[29] = fact(STACK, aux=2), fact(STACK, aux=3)
                inputs.setdefault(block['start'], []).append((tuple(entry), (), frozenset(input_values), {}, None))
            if not block['reachable']:
                assert not block['facts'] and not block['compare'] and not live_inputs and not cells and fresh is None
                assert block.get('array_continuation') is None
                continue
            state, comparison = tuple(values), compares[block['start']]
            live = declared_live[block['start']]
            spills = declared_spills[block['start']]
            stores = {}
            contents = ArrayTrace(metadata, declared_fresh[block['start']], all_writes, reg, width, read_reg,
                                  context['array_input'] if array_mode and block['start'] == start else None)
            continuation = block.get('array_continuation')
            if use_mode and result_origin is not None:
                assert continuation is None and fresh is None and not live
            if continuation is not None:
                assert graph.get('format', 4) >= 17 and type(continuation) is int and not block['entry']
                assert trace or block['start'] not in targeted or path and continuation == path['site'] and block['start'] == path['successor']
                assert (trace and trace_next.get(continuation) == block['start'] or continuation == block['start']-4) and block['start'] in continued_arrays and declared_fresh[block['start']] is None
                source, contents = continued_arrays[block['start']]
                assert source == continuation
                contents = copy.deepcopy(contents)
            fresh = declared_fresh[block['start']]
            for address in range(block['start'], block['end'], 4):
                ins = by_address[address]
                sp = state[15]
                if address in active_array_reads:
                    claim = active_array_reads[address]
                    assert all(type(claim[k]) is int for k in ('site', 'input_sp_offset', 'index', 'class_id'))
                    assert (block['start'] == start or continuation is not None) and contents.input_binding
                    assert claim['input_sp_offset'] == context['array_input']['sp_offset']
                    assert claim['index'] == contents.result_index(ins) and claim['class_id'] == contents.result(ins), 'Unproved contextual element read'
                    assert ins.operands[0].type == a.ARM64_OP_REG and width(ins, ins.operands[0].reg) == 64 and reg(ins, ins.operands[0].reg) >= 0
                    assert claim['register'] == 'x'+str(reg(ins, ins.operands[0].reg))
                    assert 0 < len(claim['proof']) <= 128 and address in claim['proof'] and all(type(p) is int and p in by_address for p in claim['proof'])
                    verified_array_reads.add(address)
                if address in active_lengths:
                    claim = active_lengths[address]
                    assert set(claim) == {'callee', 'input_sp_offset', 'register', 'length', 'value', 'allocation', 'entry_input_sp_offset', 'proof'} | ({'site'} if context else set())
                    assert all(type(claim[k]) is int for k in ('callee', 'input_sp_offset', 'length'))
                    assert claim['allocation'] is None or type(claim['allocation']) is int
                    assert claim['entry_input_sp_offset'] is None or type(claim['entry_input_sp_offset']) is int
                    proved = length_at(state, ins, contents)
                    assert proved is not None and tuple(claim[k] for k in ('callee', 'input_sp_offset', 'length', 'allocation', 'entry_input_sp_offset')) == proved[:5]
                    assert claim['register'] == 'x0' and claim['value'] == hex(claim['length'] << 1)
                    proof = claim['proof']
                    assert 0 < len(proof) <= 128 and address in proof and all(type(p) is int and p in by_address for p in proof)
                    assert claim['allocation'] is None or claim['allocation'] in proof
                    if context: verified_context_lengths.add(address)
                    else: verified_lengths.add(address)
                if (not context or trace) and address in active_indexed:
                    claim = active_indexed[address]
                    assert all(type(claim[k]) is int for k in ('callee', 'index', 'class_id'))
                    if trace:
                        assert set(claim) == {'site', 'callee', 'allocation', 'entry_input_sp_offset', 'index', 'class_id', 'register', 'proof'}
                        assert claim['allocation'] is None and type(claim['entry_input_sp_offset']) is int and claim['entry_input_sp_offset'] == context['array_input']['sp_offset']
                    else:
                        assert type(claim['allocation']) is int
                    proved = indexed_at(state, ins, contents)
                    assert proved is not None and (claim['callee'], 0 if trace else claim['allocation'], claim['index'], claim['class_id']) == proved, 'Unproved indexed result'
                    assert claim['register'] == 'x0' and 0 < len(claim['proof']) <= 128 and address in claim['proof'] and (trace or claim['allocation'] in claim['proof']) and all(type(p) is int and p in by_address for p in claim['proof'])
                    if trace: verified_trace_indexed.add(address)
                    else: verified_indexed.add(address)
                if address in active_returns:
                    claim = active_returns[address]
                    assert all(type(claim[k]) is int for k in ('callee', 'input_sp_offset', 'class_id'))
                    proved = forwarded_at(state, live, spills, ins)
                    assert proved is not None, 'Unproved forwarded result'
                    assert (claim['callee'], claim['input_sp_offset'], claim['class_id']) == proved
                    assert claim['register'] == 'x0' and 0 < len(claim['proof']) <= 128 and address in claim['proof'] and all(type(p) is int and p in by_address for p in claim['proof'])
                    if context:
                        verified_context_returns.add(address)
                    else:
                        verified_returns.add(address)
                if not context and address in array_claims:
                    assert ins.group(cs.CS_GRP_CALL) and sp[0] == STACK and contents.seed is not None
                    offsets = set()
                    for item in array_claims[address]:
                        offset = item['sp_offset']
                        assert type(offset) is int and 0 <= offset < 256 and offset % 8 == 0 and offset not in offsets
                        offsets.add(offset)
                        cell = signed(sp[1]) + offset
                        assert cell in contents.roots and cell in stores and stores[cell][0][0] == OBJECT and stores[cell][0][1] == allocations[array[0]]
                        assert type(item['allocation']) is type(item['length']) is int and (item['allocation'], item['length']) == contents.seed
                        elements = item['elements']
                        assert 0 < len(elements) <= 32 and len(dict(elements)) == len(elements)
                        for index, cid in elements:
                            assert type(index) is type(cid) is int and 0 <= index < item['length'] and contents.cells.get(array[2]+index*array[3]) == cid
                        assert 0 < len(item['proof']) <= 128 and item['allocation'] in item['proof'] and address in item['proof'] and all(type(p) is int and p in by_address for p in item['proof'])
                        array_elements_checked += len(elements)
                    verified_arrays.add(address)
                if ins.id in (a.ARM64_INS_DC, a.ARM64_INS_SYS, a.ARM64_INS_SYSL):
                    stores.clear()
                if address in active_stacks:
                    assert ins.group(cs.CS_GRP_CALL) and sp[0] == STACK
                    seen_offsets = set()
                    for item in active_stacks[address]:
                        offset = item['sp_offset']
                        assert isinstance(offset, int) and 0 <= offset < 256 and offset % 8 == 0 and offset not in seen_offsets
                        seen_offsets.add(offset)
                        stored, site = stores[signed(sp[1]) + offset]
                        assert item['kind'] == ('word' if stored[0] == WORD else 'heap_class')
                        assert int(item['value'], 16) == stored[1]
                        assert 0 < len(item['proof']) <= 128 and site in item['proof'] and all(p in by_address for p in item['proof'])
                    verified_stacks.add(address)
                if modern:
                    for m, op in enumerate(ins.operands):
                        if op.type != a.ARM64_OP_MEM:
                            continue
                        base = read_reg(state, ins, op.mem.base)
                        pair = ins.id in (a.ARM64_INS_LDP, a.ARM64_INS_STP)
                        if ins.id in (a.ARM64_INS_LDR, a.ARM64_INS_LDUR, a.ARM64_INS_LDP) and base[0] == STACK and base[2] == 0 and not ins.writeback and not op.mem.index:
                            for part in range(2 if pair else 1):
                                source = ins.operands[part]
                                if source.type != a.ARM64_OP_REG:
                                    continue
                                bits = width(ins, source.reg)
                                name = ins.reg_name(source.reg)
                                name = {'fp': 'x29', 'lr': 'x30'}.get(name, name)
                                key = address, name
                                if key in active_loads:
                                    item = active_loads[key]
                                    offset = signed(base[1]) + op.mem.disp + part * (bits // 8)
                                    assert 0 <= offset < 256 and bits in (32, 64)
                                    assert (item['payload'], item['entry_sp_offset'], item['width']) == (start, offset, bits // 8)
                                    assert 0 < len(item['proof']) <= 128 and address in item['proof'] and all(p in by_address for p in item['proof'])
                                    verified_loads.add(key)
                        if not memory_write(ins, op):
                            continue
                        field = heap_field(base, op, ins.writeback, metadata['header_displacement'], heap_address_enabled)
                        if field:
                            continue
                        supported = ins.id in (a.ARM64_INS_STR, a.ARM64_INS_STUR, a.ARM64_INS_STP) and not ins.writeback and not op.mem.index and base[0] == sp[0] == STACK and base[2] == sp[2]
                        supported = supported and all(v.type == a.ARM64_OP_REG and width(ins, v.reg) == 64 for v in ins.operands[:2 if pair else 1])
                        if not supported:
                            stores.clear()
                            continue
                        for part in range(2 if pair else 1):
                            offset = signed(base[1]) + op.mem.disp + part * 8
                            if not -(1 << 63) <= offset < 1 << 63 or offset % 8:
                                stores.clear()
                                continue
                            stores.pop(offset, None)
                            if len(stores) >= 256:
                                stores.clear()
                            value = read_reg(state, ins, ins.operands[part].reg)
                            if value[0] in (WORD, OBJECT):
                                stores[offset] = value, address
                if address in active_claims:
                    assert ins.id == a.ARM64_INS_BLR
                    value = read_reg(state, ins, ins.operands[0].reg)
                    claim = active_claims[address]
                    assert value[0] == TARGET
                    assert (claim['table_index'], claim['index'], claim['load'], claim['snapshot_target']) == (value[1], signed(value[2]), value[3], dispatch['entries'][value[1]])
                    assert claim['proof'] and all(p in by_address for p in claim['proof']) and value[3] in claim['proof']
                    if context:
                        assert address not in claims or claims[address]['snapshot_target'] == claim['snapshot_target']
                        verified_context.add(address)
                    else:
                        verified[address] = claim
                state, comparison, live, spills, fresh = step(state, comparison, live, spills, ins, contents)
                if ins.group(cs.CS_GRP_CALL) or ins.group(cs.CS_GRP_INT) or sp[0] != state[15][0] or sp[2] != state[15][2]:
                    stores.clear()
            edges = outgoing(block, state, comparison, live, spills, fresh)
            if trace:
                expected = trace_next.get(block['end']-4)
                assert len(edges) == (0 if expected is None else 1)
                assert expected is None or edges[0][0] == expected, 'Unproved prefix edge'

            outgoing_edges[block['start']] = edges
            for address, incoming, flags, incoming_live, incoming_spills, incoming_fresh in edges:
                inputs.setdefault(address, []).append((incoming, flags, incoming_live, incoming_spills, incoming_fresh))
            blocks_checked += 1
        reachable, queue = set(), deque(b['start'] for b in blocks if b['entry'])
        while queue:
            address = queue.popleft()
            if address in reachable:
                continue
            reachable.add(address)
            assert address in outgoing_edges
            queue.extend(e[0] for e in outgoing_edges[address])
        assert reachable == {b['start'] for b in blocks if b['reachable']}
        for address in reachable:
            for incoming, flags, incoming_live, incoming_spills, incoming_fresh in inputs[address]:
                assert declared_fresh[address] is None or declared_fresh[address] == incoming_fresh
                assert all(entails(source, dest) for source, dest in zip(incoming, declared[address])), (hex(address), incoming, declared[address])
                assert not compares[address] or compares[address] == flags
                assert declared_live[address] <= incoming_live
                assert all(incoming_spills.get(k) == v for k, v in declared_spills[address].items())
                incoming_checks += 1
        if use_mode:
            assert result_origin == trace['getter']
            result_use_count += len(verified_context)
        if trace:
            assert verified_trace_indexed == set(active_indexed)
            if use_mode: result_indexed_count += len(verified_trace_indexed)
            else: entry_result_count += len(verified_trace_indexed)
        if context:
            assert verified_context == set(active_claims), 'Missing context resolution certificate'
            assert verified_context_returns == set(active_returns), 'Missing contextual forwarded-result certificate'
            assert verified_context_lengths == set(active_lengths), 'Missing contextual length-result certificate'
            if use_mode:
                result_length_count += len(verified_context_lengths)
            elif trace:
                entry_length_count += len(verified_context_lengths)
            elif path:
                path_length_count += len(verified_context_lengths)
            else:
                contextual_lengths += len(verified_context_lengths)
            if array_mode:
                assert verified_array_reads == set(active_array_reads), 'Missing array read certificate'
                if use_mode:
                    result_read_count += len(verified_array_reads)
                elif trace:
                    entry_read_count += len(verified_array_reads)
                    entry_dispatch_count += len(verified_context)
                elif path:
                    path_read_count += len(verified_array_reads)
                    path_dispatch_count += len(verified_context)
                else:
                    array_context_read_count += len(verified_array_reads)
                    array_context_dispatch_count += len(verified_context)
            else:
                context_return_count += len(verified_context_returns)
                context_results += len(verified_context)
    assert set(verified) == set(claims), 'Missing or duplicate receiver certificate'
    assert verified_arrays == set(array_claims), 'Missing array-argument certificate'
    assert verified_indexed == set(indexed_claims), 'Missing indexed-result certificate'
    assert verified_returns == set(return_claims), 'Missing forwarded-result certificate'
    assert verified_lengths == set(length_claims), 'Missing length-result certificate'
    assert verified_stacks == set(stack_claims), 'Missing stack-input certificate'
    assert verified_loads == set(load_claims), 'Missing entry-stack-load certificate'
    assert context_callers <= verified_stacks, 'Unchecked context caller observations'
    assert array_context_callers <= verified_arrays, 'Unchecked array context caller observations'
    return {'receiver_claims_checked': len(verified), 'receiver_blocks_checked': blocks_checked,
            'receiver_incoming_edges_checked': incoming_checks, 'receiver_pool_class_inputs_checked': len(pools),
            'receiver_allocation_inputs_checked': len(allocations), 'stack_input_calls_checked': len(verified_stacks),
            'stack_input_slots_checked': sum(map(len, stack_claims.values())), 'entry_stack_loads_checked': len(verified_loads),
            'thread_class_inputs_checked': len(thread_classes), 'call_contexts_checked': len(contexts),
            'context_dispatches_checked': context_results, 'context_callers_checked': len(context_callers),
            'prefix_call_effects_checked': len(prefix_safe), 'prefix_effect_instructions_checked': prefix_instructions,
            'call_effects_checked': len(legacy_safe), 'call_effect_instructions_checked': effect_instructions,
            'nonreturning_call_inputs_checked': len(nonreturning_calls),
            'array_return_summaries_checked': len(legacy_arrays),
            'array_length_calls_checked': len(verified_lengths), 'context_array_length_calls_checked': contextual_lengths,
            'indexed_return_calls_checked': len(verified_indexed),
            'forwarded_input_summaries_checked': len(return_inputs),
            'forwarded_return_calls_checked': len(verified_returns),
            'context_forwarded_returns_checked': context_return_count,
            'array_result_traces_checked': len(result_traces), 'array_result_dispatches_checked': result_use_count,
            'array_result_indexed_results_checked': result_indexed_count, 'array_result_lengths_checked': result_length_count, 'array_result_reads_checked': result_read_count,
            'array_entry_traces_checked': len(entry_traces), 'array_entry_results_checked': entry_result_count,
            'array_entry_lengths_checked': entry_length_count, 'array_entry_reads_checked': entry_read_count, 'array_entry_dispatches_checked': entry_dispatch_count,
            'array_path_contexts_checked': len(path_contexts), 'array_path_reads_checked': path_read_count,
            'array_path_dispatches_checked': path_dispatch_count, 'array_path_lengths_checked': path_length_count,
            'array_contexts_checked': len(array_contexts), 'array_context_callers_checked': len(array_context_callers),
            'array_context_reads_checked': array_context_read_count, 'array_context_dispatches_checked': array_context_dispatch_count,
            'array_argument_calls_checked': len(verified_arrays), 'array_argument_elements_checked': array_elements_checked}
