"""Check bounded Boolean selections from original words and field certificates."""
from collections import Counter
import struct

from field_branch_uses import signed, check_stream as check_comment_stream

FIELDS = ('field_decision_abi', 'field_decisions')


def constant(word, abi):
    if (word & 0xffc00000) != 0x91000000 or ((word >> 5) & 31) != 22 or (word & 31) > 28 or (word & 31) == 22:
        return None
    value = (word >> 10) & 0xfff
    if value == abi['true_offset']:
        return True
    if value == abi['false_offset']:
        return False
    return None


def check_decisions(graph, audit, read):
    if graph.get('format', 0) < 48:
        return 0
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, CS_GRP_JUMP, CS_GRP_CALL
    from capstone.arm64 import ARM64_OP_IMM
    from check_snapshot_annotations import decode_payload
    from async_field_accesses import expected_layout

    abi = graph['field_decision_abi']
    assert abi == audit['field_decision_abi']
    expected = []
    if not abi['supported'] or graph['receiver_metadata']['null_register'] != 'x22':
        assert graph['field_decisions'] == []
        return 0
    assert 0 < abi['true_offset'] != abi['false_offset'] > 0
    decoder = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    decoder.detail = True
    nodes = {n['start']: n['end'] for n in graph['nodes']}
    layouts = {l['class_id']: l for l in graph['async_field_layouts']}
    bodies = {b['payload']: b for b in graph['future_binding_bodies']}
    entries = set(graph['receiver_metadata']['entries'])
    decoded = {}
    for ui, use in enumerate(graph['field_branch_uses']):
        context = graph['joined_reference_contexts'][use['context']]
        reference = context['observations'][use['reference']]
        payload = context['payload']
        if payload not in decoded:
            code = read(payload, nodes[payload] - payload)
            incoming = {}
            for i in decode_payload(decoder, code, payload):
                if ((i.group(CS_GRP_JUMP) or i.group(CS_GRP_CALL)) and i.operands
                        and i.operands[-1].type == ARM64_OP_IMM):
                    incoming.setdefault(i.operands[-1].imm, set()).add(i.address)
            decoded[payload] = code, incoming
        code, incoming = decoded[payload]
        pc = use['site']
        if pc + 44 > nodes[payload]:
            continue
        words = struct.unpack_from('<11I', code, pc - payload)
        if (use['set_target'], use['clear_target']) == (pc + 36, pc + 4):
            on_set = True
        elif (use['clear_target'], use['set_target']) == (pc + 36, pc + 4):
            on_set = False
        else:
            continue
        external = entries | set(bodies[payload]['handlers'])
        if any(pc + 4*n in external or
               incoming.get(pc + 4*n, set()) - ({pc} if n == 9 else {pc + 32} if n == 10 else set())
               for n in range(1, 11)):
            continue
        if (words[0] & 31) in (22, reference['register']):
            continue
        load = words[1]
        if (load & 0xffc00000) == 0xb9400000:
            disp = ((load >> 10) & 0xfff) * 4
        elif (load & 0xffe00c00) in (0xb8400000, 0xb8400800):
            disp = signed((load >> 12) & 0x1ff, 9)
        else:
            continue
        layout = layouts[context['class_id']]
        assert layout == expected_layout(context['class_id'], audit)
        offset = disp + layout['tag']
        reg = load & 31
        if (disp < 0 or ((load >> 5) & 31) != reference['register'] or reg in (22, 31)
                or not layout['header'] <= offset <= layout['end'] - 4 or offset % 4
                or offset in layout['excluded'] or offset in layout['unboxed']):
            continue
        if words[2] != (0x8b1c8000 | (reg << 5) | reg) or words[3] != (0x6b16001f | (reg << 5)):
            continue
        first, second, fallback = (constant(words[n], abi) for n in (4, 5, 9))
        if first is None or second is None or fallback is not False or first == second:
            continue
        a, b, out = words[4] & 31, words[5] & 31, words[6] & 31
        select = words[6]
        cc = (select >> 12) & 15
        if (a == b or out > 28 or cc not in (0, 1)
                or select != (0x9a800000 | (b << 16) | (cc << 12) | (a << 5) | out)):
            continue
        result = words[7] & 31
        if result > 28 or words[7] != (0xaa0003e0 | (out << 16) | result) or (words[9] & 31) != result:
            continue
        if words[8] != 0x14000002:
            continue
        store = words[10]
        slot = signed((store >> 12) & 0x1ff, 9)
        if (store & 0xffe00c00) != 0xf8000000 or ((store >> 5) & 31) != 29 or (store & 31) != result or slot >= 0 or slot % 8:
            continue
        expected.append(dict(branch_use=ui, load=pc+4, site=pc+40, offset=offset,
                             fp_offset=slot, register=result, on_set=on_set,
                             non_null_true=first if cc == 1 else second))

    assert graph['field_decisions'] == expected, 'Field decision differs from the checked machine-code diamond'
    return len(expected)


def note(graph, decision):
    use = graph['field_branch_uses'][decision['branch_use']]
    context = graph['joined_reference_contexts'][use['context']]
    reload = context['observations'][use['reference']]['site']
    return (f"field decision: (bit {use['bit']} of read {reload+4:#x} "
            f"{'clear' if decision['on_set'] else 'set'}) && (read {decision['load']:#x} "
            f"{'!=' if decision['non_null_true'] else '=='} null); Boolean X{decision['register']} "
            f"saved to FP{decision['fp_offset']:+d} [conditional on joined reload {reload:#x}]")


def expected_notes(graph):
    return Counter((d['site'], note(graph, d)) for d in graph['field_decisions'])


def check_stream(stream, expected):
    return check_comment_stream(stream, expected, prefix='field decision:')


def check_output(graph, output):
    import json
    from native_assembly import native_assembly_streams
    expected = expected_notes(graph)
    seen = Counter()
    manifest = json.loads((output/'snapshot_code.json').read_text())
    for _, stream in native_assembly_streams(output, manifest):
        seen.update(check_stream(stream, expected))
    assert seen == expected, 'Missing or duplicate field decision comments'
    return sum(seen.values())
