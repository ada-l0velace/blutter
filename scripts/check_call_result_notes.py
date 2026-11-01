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


PREFIX = re.compile(r'^\s*// caller-result @(0x[0-9a-f]+) \[payload (0x[0-9a-f]+)\]: (.*)$')
INSTRUCTION = re.compile(r'^\s*//\s*(0x[0-9a-f]+):\s+([a-z][a-z0-9.]*)\b')


def expected_facts(graph):
    edges = {e['site']: e for e in graph['edges']}
    facts = set()
    for c in graph.get('call_result_contexts', []):
        payload = c['payload']
        for b in c['return_bindings']:
            basis = 'callee summary' if b['basis'] == 'machine_return_summary' else 'caller-bound helper'
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
    return facts


def parse_note(line, class_names=None):
    match = PREFIX.fullmatch(line.rstrip('\n'))
    assert match, 'Malformed caller-result annotation'
    site, payload = int(match[1], 16), int(match[2], 16)
    body = match[3]
    name = re.search(r' \(("(?:[^"\\]|\\.)*")\)', body)
    if name:
        displayed_name = ast.literal_eval(name[1])
        body = body[:name.start()] + body[name.end():]
    cid = None
    m = re.fullmatch(r'normal-return X0 -> class (0x[0-9a-f]+) \[(callee summary|caller-bound helper)\]', body)
    if m:
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


def check_stream(lines, expected, class_names=None, instruction_kinds=None):
    by_site = defaultdict(set)
    for fact in expected:
        by_site[fact[1]].add(fact)
    observed, required = Counter(), Counter()
    pending, kinds, previous = [], {}, None
    for line in lines:
        if instruction_kinds is not None and re.search(r'// \*\* addr:', line):
            previous = None
        if re.match(r'^\s*// caller-result', line):
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
    expected = expected_facts(graph)
    catalogue = output / 'blutter_frida.js'
    class_names = metadata_class_names(catalogue.read_text()) if catalogue.exists() else None
    with (output / 'asm/snapshot_code.asm').open() as stream:
        native, kinds = check_stream(stream, expected, class_names)
    assert set(native) == expected, 'Native assembly omits a checked result fact'
    typed_count = files = 0
    for path in (output / 'asm').rglob('*.dart'):
        with path.open() as stream:
            try:
                typed, _ = check_stream(stream, expected, class_names, kinds)
            except AssertionError as error:
                raise AssertionError(f'{path}: {error}') from error
        typed_count += sum(typed.values()); files += bool(typed)
    return {'status': 'PASSED', 'expected_facts': len(expected), 'native_notes': sum(native.values()),
            'typed_notes': typed_count, 'typed_files_with_notes': files,
            'class_name_scope': 'Retained non-predefined names; predefined Frida aliases excluded. Numeric classes and scopes are checked for every note.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    graph = json.loads((args.output / 'snapshot_calls.json').read_text())
    print(json.dumps(check_output(graph, args.output), indent=2))


if __name__ == '__main__':
    main()
