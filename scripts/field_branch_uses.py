"""Replay field bit tests from original ARM64 words and checked joined reloads."""
from collections import Counter, defaultdict
import json
import re
import struct

FIELDS = ('field_branch_uses', 'field_branch_work')


def signed(value, bits):
    return value - (1 << bits) if value & (1 << (bits - 1)) else value


def check_branches(graph, audit, read):
    if graph.get('format', 0) < 47:
        return 0
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, CS_GRP_JUMP, CS_GRP_CALL
    from capstone.arm64 import ARM64_OP_IMM
    from async_field_accesses import expected_layout
    from check_snapshot_annotations import decode_payload

    work = dict(candidates=0, bytes=0)
    expected = []
    contexts = defaultdict(list)
    layouts = {l['class_id']: l for l in graph['async_field_layouts']}
    if graph['receiver_metadata']['heap_bits_register'] == 'x28':
        for i, context in enumerate(graph['joined_reference_contexts']):
            layout = layouts.get(context['class_id'])
            if context['observations'] and layout and layout['kind'] == 'instance' and layout['slot_bytes'] == 4:
                assert audit['heap_bits_register'] == 'x28'
                assert layout == expected_layout(context['class_id'], audit)
                contexts[context['payload']].append((i, context, layout))

    if contexts:
        decoder = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
        decoder.detail = True
        entries = set(graph['receiver_metadata']['entries'])
        handlers = {b['payload']: b['handlers'] for b in graph['future_binding_bodies']}
        ends = {n['start']: n['end'] for n in graph['nodes']}
        for payload, group in sorted(contexts.items()):
            end = ends[payload]
            code = read(payload, end - payload)
            work['bytes'] += len(code)
            targets = entries | set(handlers[payload])
            for insn in decode_payload(decoder, code, payload):
                if ((insn.group(CS_GRP_JUMP) or insn.group(CS_GRP_CALL)) and insn.operands
                        and insn.operands[-1].type == ARM64_OP_IMM):
                    targets.add(insn.operands[-1].imm)

            for i, context, layout in group:
                for j, reference in enumerate(context['observations']):
                    work['candidates'] += 1
                    field = reference['site'] + 4
                    site = field + 8
                    if site + 4 >= end or targets.intersection((field, field + 4, site)):
                        continue
                    load, add, branch = struct.unpack_from('<III', code, field - payload)
                    if load & 0xffc00000 == 0xb9400000:
                        disp = ((load >> 10) & 0xfff) * 4
                    elif load & 0xffe00c00 in (0xb8400000, 0xb8400800):
                        disp = signed((load >> 12) & 0x1ff, 9)
                    else:
                        continue
                    if ((load >> 5) & 31) != reference['register'] or disp < 0:
                        continue
                    offset = disp + layout['tag']
                    if (not layout['header'] <= offset <= layout['end'] - 4 or offset % 4
                            or offset in layout['excluded'] or offset in layout['unboxed']):
                        continue
                    reg = load & 31
                    if reg == 31 or add != (0x8b1c8000 | (reg << 5) | reg):
                        continue
                    # Mask both TBZ/TBNZ forms while requiring the low-word bit range.
                    if (branch & 0xfe00001f) != (0x36000000 | reg):
                        continue
                    target = site + 4 * signed((branch >> 5) & 0x3fff, 14)
                    if not payload <= target < end:
                        continue
                    set_target, clear_target = (target, site + 4) if branch & (1 << 24) else (site + 4, target)
                    expected.append(dict(context=i, reference=j, site=site, offset=offset,
                                         bit=(branch >> 19) & 31, set_target=set_target,
                                         clear_target=clear_target))

    assert work == graph['field_branch_work'], 'Field-branch work differs from eligible reloads'
    assert expected == graph['field_branch_uses'], 'Field-branch evidence differs from original instructions'
    return len(expected)


def note(graph, use):
    context = graph['joined_reference_contexts'][use['context']]
    reload = context['observations'][use['reference']]['site']
    return (f"field bit test: bit {use['bit']} of word loaded at {reload + 4:#x} "
            f"from class {context['class_id']:#x} instance slot {use['offset']:#x}; "
            f"set -> {use['set_target']:#x}, clear -> {use['clear_target']:#x} "
            f"[conditional on joined reload {reload:#x} from await {context['source_await']:#x}]")


def expected_notes(graph):
    return Counter((use['site'], note(graph, use)) for use in graph['field_branch_uses'])


def check_stream(stream, expected, *, prefix='field bit test:'):
    by_site = defaultdict(Counter)
    for (site, comment), count in expected.items():
        by_site[site][comment] = count
    pending = []
    seen = Counter()
    for line in stream:
        if prefix in line:
            assert line.strip().startswith('// ' + prefix)
            pending.append(line.strip()[3:])
        match = re.match(r'^\s*// (0x[0-9a-f]+):', line)
        if match:
            site = int(match[1], 16)
            if pending or site in by_site:
                assert Counter(pending) == by_site.get(site, {}), 'Misplaced or incorrect field bit test comment'
                seen.update((site, comment) for comment in pending)
                pending.clear()
    assert not pending
    return seen


def check_output(graph, output):
    from native_assembly import native_assembly_streams
    expected = expected_notes(graph)
    manifest = json.loads((output / 'snapshot_code.json').read_text())
    seen = Counter()
    for _, stream in native_assembly_streams(output, manifest):
        seen.update(check_stream(stream, expected))
    assert seen == expected, 'Missing or duplicate field bit test comments'
    return sum(seen.values())
