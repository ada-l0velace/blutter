#!/usr/bin/env python3
"""Check assembly presentation against the separately checked call-result graph.

This checks rendering and coverage. Original-word/SDK proof checking remains in
check_snapshot_annotations.py; matching text alone does not validate a type.
"""
import argparse
import ast
from collections import Counter, defaultdict
import json
from pathlib import Path
import re
from native_assembly import native_assembly_streams
from indirect_result_records import indirect_results, scope_key
from stub_input_roles import input_records, ROLE_TEXT
from call_input_shapes import input_records as supplied_input_records


PREFIX = re.compile(r'^\s*// caller-result @(0x[0-9a-f]+) \[payload (0x[0-9a-f]+)\]: (.*)$')
INPUT_PREFIX = re.compile(r'^\s*// call-input @(0x[0-9a-f]+) \[payload (0x[0-9a-f]+)\]: (.*)$')
INSTRUCTION = re.compile(r'^\s*//\s*(0x[0-9a-f]+):\s+([a-z][a-z0-9.]*)\b')


def expected_facts(graph):
    edges = {e['site']: e for e in graph['edges']}
    facts = set()
    for value in input_records(graph):
        scope = scope_key([], [], value['bindings']) if value['bindings'] is not None else None
        if value['role']:
            facts.add((value['payload'], value['site'], 'role_input', value['register'], value['role'],
                       value['callee'], value['kind'], value['value'], scope))
        else:
            facts.add((value['payload'], value['site'], 'input', value['register'], value['value'], scope))
    for value in supplied_input_records(graph):
        scope = scope_key([], [], value['bindings']) if value['bindings'] is not None else None
        facts.add((value['payload'], value['site'], 'supplied_input', value['index'], value['sp_offset'],
                   value['kind'], value['value'], value['load'], scope))
    for c in (graph.get('call_result_contexts', []) + graph.get('sdk_stub_producer_contexts', []) +
              graph.get('sdk_stub_caller_contexts', [])):
        payload = c['payload']
        for b in c['return_bindings']:
            basis = {'machine_return_summary': 'callee summary', 'register_context': 'caller-bound helper',
                     'sdk_stub_identity': 'matched SDK stub', 'sdk_stub_summary': 'SDK-derived helper'}[b['basis']]
            facts.add((payload, b['site'], 'normal', b['class_id'], basis))
        for o in c['stack_observations']:
            before = {(v['sp_offset'], v['kind'], int(v['value'], 16)) for v in edges[o['site']]['stack_inputs']}
            after = {(v['sp_offset'], v['kind'], int(v['value'], 16)) for v in o['values']}
            for offset, kind, value in after - before:
                facts.add((payload, o['site'], 'stack', offset, kind, value))
        for o in c['array_observations']:
            before = {(v['sp_offset'], v['allocation'], i, cid)
                      for v in edges[o['site']]['array_arguments'] for i, cid in v['elements']}
            for a in o['values']:
                for i, cid in a['elements']:
                    if (a['sp_offset'], a['allocation'], i, cid) not in before:
                        facts.add((payload, o['site'], 'array', a['sp_offset'], a['allocation'], a['length'], i, cid))
        for d in c['resolutions']:
            facts.add((payload, d['site'], 'dispatch', d['snapshot_target']))
        for v in c['certificate'].get('return_classes', []):
            facts.add((payload, v['site'], 'ret', v['class_id']))
    for row in indirect_results(graph):
        facts.add((row['payload'], row['site'], 'indirect', row['class_id'], row['callee'],
                   scope_key(row['entry_register_inputs'], row['entry_stack_inputs'], row['return_bindings'])))
    return facts


def parse_scope(registers, stack, calls):
    def values(text, pattern, convert, limit):
        if text == 'none':
            return ()
        parts = text.split(',')
        assert 0 < len(parts) <= limit, 'Invalid indirect-result scope size'
        matches = [re.fullmatch(pattern, part) for part in parts]
        assert all(matches), 'Malformed indirect-result condition'
        result = tuple(convert(m) for m in matches)
        assert len({v[0] for v in result}) == len(result), 'Duplicate indirect-result condition'
        return tuple(sorted(result))
    return (values(registers, r'x(\d+)=(0x[0-9a-f]+)', lambda m: (int(m[1]), int(m[2], 16)), 15),
            values(stack, r'SP\+(\d+):(word|heap_class)=(0x[0-9a-f]+)',
                   lambda m: (int(m[1]), m[2], int(m[3], 16)), 32),
            values(calls, r'(0x[0-9a-f]+)@(0x[0-9a-f]+)=(0x[0-9a-f]+)',
                   lambda m: tuple(int(m[k], 16) for k in (1, 2, 3)), 16384))


def parse_note(line, class_names=None):
    input_match = INPUT_PREFIX.fullmatch(line.rstrip('\n'))
    match = input_match or PREFIX.fullmatch(line.rstrip('\n'))
    assert match, 'Malformed caller-result annotation'
    site, payload = int(match[1], 16), int(match[2], 16)
    body = match[3]
    name = re.search(r' \(("(?:[^"\\]|\\.)*")\)', body)
    if name:
        displayed_name = ast.literal_eval(name[1])
        body = body[:name.start()] + body[name.end():]
    cid = None
    m = re.fullmatch(r'normal-return X0 -> class (0x[0-9a-f]+) \[(callee summary|caller-bound helper|matched SDK stub|SDK-derived helper)\]', body)
    if input_match:
        supplied = re.fullmatch(r'supplied input\[(\d+)\] \(Dart SP\+(\d+)\) -> (class|raw word) (0x[0-9a-f]+) \[descriptor load (0x[0-9a-f]+); fixed stack; partial; (.*)\]', body)
        if supplied:
            condition = supplied[6]
            if condition == 'normal flow':
                scope = None
            else:
                binding = re.fullmatch(r'under result bindings (.+)', condition)
                assert binding, 'Supplied input lacks its conditions'
                scope = parse_scope('none', 'none', binding[1])
                assert scope[2], 'Supplied input has empty conditions'
            kind = 'heap_class' if supplied[3] == 'class' else 'word'
            amount = int(supplied[4], 16)
            cid = amount if kind == 'heap_class' else None
            fact = (payload, site, 'supplied_input', int(supplied[1]), int(supplied[2]), kind, amount, int(supplied[5], 16), scope)
            if name:
                assert cid is not None, 'Raw input word cannot carry a class name'
                if class_names is not None and cid in class_names:
                    assert displayed_name == class_names[cid], 'Supplied input class name differs from metadata'
            elif class_names is not None and cid in class_names and class_names[cid]:
                raise AssertionError('Available supplied input class name is missing')
            return fact
        role_value = re.fullmatch(r'(.+) \(X(\d+)\) -> (class (0x[0-9a-f]+)|raw word (0x[0-9a-f]+)|value unknown) \[stub (0x[0-9a-f]+); partial; (.*)\]', body)
        value = re.fullmatch(r'physical (x\d+) -> class (0x[0-9a-f]+) \[partial; (.*)\]', body)
        assert value or role_value, 'Malformed register input annotation'
        condition_text = role_value[7] if role_value else value[3]
        if condition_text == 'normal flow':
            scope = None
        else:
            condition = re.fullmatch(r'under result bindings (.+)', condition_text)
            assert condition, 'Register input annotation lacks its conditions'
            scope = parse_scope('none', 'none', condition[1])
            assert scope[2] and not scope[0] and not scope[1], 'Unexpected register input scope'
        if role_value:
            roles = {text: role for role, text in ROLE_TEXT.items()}
            assert role_value[1] in roles, 'Unknown SDK input role'
            kind = 'class' if role_value[4] else 'word' if role_value[5] else 'unknown'
            amount = int(role_value[4] or role_value[5], 16) if kind != 'unknown' else None
            cid = amount if kind == 'class' else None
            fact = (payload, site, 'role_input', 'x' + role_value[2], roles[role_value[1]],
                    int(role_value[6], 16), kind, amount, scope)
        else:
            cid = int(value[2], 16)
            fact = (payload, site, 'input', value[1], cid, scope)
    elif (indirect := re.fullmatch(r'indirect normal-return X0 -> class (0x[0-9a-f]+) \[callee (0x[0-9a-f]+); entry regs ([^;]+); stack ([^;]+); after calls ([^;]+)\]', body)):
        cid = int(indirect[1], 16)
        fact = (payload, site, 'indirect', cid, int(indirect[2], 16), parse_scope(*indirect.groups()[2:]))
    elif m:
        cid = int(m[1], 16); fact = (payload, site, 'normal', cid, m[2])
    elif (m := re.fullmatch(r'stack Dart SP([+-]\d+) -> (class|word) (0x[0-9a-f]+) \[partial\]', body)):
        value = int(m[3], 16); kind = 'heap_class' if m[2] == 'class' else 'word'
        cid = value if kind == 'heap_class' else None
        fact = (payload, site, 'stack', int(m[1]), kind, value)
    elif (m := re.fullmatch(r'array Dart SP([+-]\d+), allocation (0x[0-9a-f]+), length (\d+), element\[(\d+)\] -> class (0x[0-9a-f]+) \[partial\]', body)):
        cid = int(m[5], 16)
        fact = (payload, site, 'array', int(m[1]), int(m[2], 16), int(m[3]), int(m[4]), cid)
    elif (m := re.fullmatch(r'snapshot dispatch -> (0x[0-9a-f]+)', body)):
        fact = (payload, site, 'dispatch', int(m[1], 16))
    elif (m := re.fullmatch(r'physical X0 at RET -> class (0x[0-9a-f]+)', body)):
        cid = int(m[1], 16); fact = (payload, site, 'ret', cid)
    else:
        raise AssertionError('Unknown or unscoped caller-result annotation')
    if name:
        assert cid is not None, 'A word or dispatch target cannot carry an object class name'
        if class_names is not None and cid in class_names:
            assert displayed_name == class_names[cid], 'Class display name disagrees with metadata'
    elif class_names is not None and cid in class_names and class_names[cid]:
        raise AssertionError('Available class display name is missing')
    return fact


def facts_by_site(expected):
    index = defaultdict(set)
    for fact in expected:
        index[fact[1]].add(fact)
    return index


def check_stream(lines, expected, class_names=None, instruction_kinds=None, *, by_site=None):
    if by_site is None:
        by_site = facts_by_site(expected)
    observed, required = Counter(), Counter()
    pending, kinds, previous = [], {}, None
    for line in lines:
        if instruction_kinds is not None and re.search(r'// \*\* addr:', line):
            previous = None
        if re.match(r'^\s*// (?:caller-result|call-input)', line):
            fact = parse_note(line, class_names)
            assert fact in expected, 'Assembly annotation has no corresponding checked graph fact'
            observed[fact] += 1; pending.append(fact[1])
            continue
        m = INSTRUCTION.match(line)
        if not m:
            continue
        site, mnemonic = int(m[1], 16), m[2]
        if instruction_kinds is not None and instruction_kinds.get(site) != mnemonic:
            continue  # Dart IL summaries are not raw machine instructions.
        kinds[site] = mnemonic
        if pending:
            assert all(s == site for s in pending), 'Annotation is attached to another instruction'
            pending.clear()
        # A typed function can print an IL "ret" and its raw RET at the same
        # address. Shared-code functions remain separate after their headers.
        if instruction_kinds is None or previous != (site, mnemonic):
            required.update(by_site.get(site, ()))
        previous = site, mnemonic
    assert not pending, 'Annotation has no following original instruction'
    assert observed == required, ('Missing or duplicate assembly annotations',
                                  list((required - observed).items())[:3], list((observed - required).items())[:3])
    return observed, kinds


def metadata_class_names(script):
    # Frida deliberately renames predefined VM implementations (for example,
    # _List -> List). They are display aliases, not the raw VM class names.
    boundary = re.search(r'const NumPredefinedCids = (\d+);', script)
    assert boundary, 'Missing matched predefined-class boundary'
    return {int(cid): json.loads(name)
            for cid, name in re.findall(r'\{id:(\d+),name:("(?:[^"\\]|\\.)*")', script)
            if int(cid) >= int(boundary[1])}


def check_output(graph, output):
    from closure_capture_transfers import check_output as check_closure_captures
    closure_capture_notes=check_closure_captures(graph,output) if graph.get('format',0)>=50 else 0
    from decision_branch_uses import check_output as check_decision_branches
    decision_branches = check_decision_branches(graph,output) if graph.get('format',0) >= 49 else 0
    from field_decisions import check_output as check_decision_output
    decision_notes = check_decision_output(graph, output) if graph.get('format', 0) >= 48 else 0
    from field_branch_uses import check_output as check_branch_output
    branch_notes = check_branch_output(graph, output) if graph.get('format', 0) >= 47 else 0
    from joined_async_references import check_output as check_joined_output
    joined_notes = check_joined_output(graph, output) if graph.get('format', 0) >= 46 else 0
    from callee_entry_reads import check_output as check_entry_output
    entry_notes = check_entry_output(graph, output) if graph.get('format', 0) >= 45 else 0
    from fresh_content_uses import check_output as check_contents_output
    content_notes = check_contents_output(graph, output) if graph.get('format', 0) >= 44 else 0
    from fresh_field_initializations import check_output as check_fresh_output
    fresh_notes = check_fresh_output(graph, output) if graph.get("format", 0) >= 43 else 0
    from captured_field_values import check_output as check_captured_output
    captured_notes = check_captured_output(graph, output) if graph.get("format", 0) >= 42 else 0
    from field_input_origins import check_output as check_field_input_output
    field_input_notes = check_field_input_output(graph, output) if graph.get('format', 0) >= 41 else 0
    from async_field_accesses import check_output as check_field_output
    field_notes = check_field_output(graph, output) if graph.get('format', 0) >= 40 else 0
    from saved_async_references import check_saved_output
    saved_notes=check_saved_output(graph,output) if graph.get('format',0)>=39 else 0
    expected = expected_facts(graph)
    from async_future_bindings import check_binding_output
    future_notes = check_binding_output(graph, output) if graph.get('format',0) >= 38 else 0
    by_site = facts_by_site(expected)
    catalogue = output / 'blutter_frida.js'
    class_names = metadata_class_names(catalogue.read_text()) if catalogue.exists() else None
    manifest_path = output / 'snapshot_code.json'
    manifest = json.loads(manifest_path.read_text()) if manifest_path.exists() else {}
    native, kinds = Counter(), {}
    for _, stream in native_assembly_streams(output, manifest):
        observed, found = check_stream(stream, expected, class_names, by_site=by_site)
        native.update(observed)
        kinds.update(found)
    assert set(native) == expected, 'Native assembly omits a checked result fact'
    typed_count = files = 0
    for path in (output / 'asm').rglob('*.dart'):
        with path.open() as stream:
            try:
                typed, _ = check_stream(stream, expected, class_names, kinds, by_site=by_site)
            except AssertionError as error:
                raise AssertionError(f'{path}: {error}') from error
        typed_count += sum(typed.values()); files += bool(typed)
    return {'status': 'PASSED', 'expected_facts': len(expected), 'native_notes': sum(native.values()), 'container_input_notes': content_notes,
            'typed_notes': typed_count, 'container_consumer_notes': entry_notes, 'joined_reference_notes': joined_notes, 'field_branch_notes': branch_notes, 'field_decision_notes': decision_notes, 'decision_branch_notes': decision_branches, 'closure_capture_notes': closure_capture_notes, 'conditional_await_notes': future_notes, 'restored_reference_notes': saved_notes, 'async_field_notes': field_notes, 'field_input_notes': field_input_notes, 'captured_field_notes': captured_notes, 'fresh_field_notes': fresh_notes, 'typed_files_with_notes': files,
            'class_name_scope': 'Retained non-predefined names; predefined Frida aliases excluded. Numeric classes and scopes are checked for every note.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    from graph_io import load_graph
    graph = load_graph(args.output)
    print(json.dumps(check_output(graph, args.output), indent=2))


if __name__ == '__main__':
    main()
