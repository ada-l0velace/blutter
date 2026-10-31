"""Independently validate the scope of an initial stack-check fast path.

This excludes an edge under an explicit condition. It does not certify the
runtime helper as read-only, heap-preserving or nonreturning.
"""
from check_snapshot_annotations import branch


def check_initial_stack_check(context, instructions, graph, audit, external, condition=None):
    initial = condition is None
    condition = context['path_condition'] if initial else condition
    assert set(condition) == {'edge', 'site', 'successor', 'slow_path', 'stub', 'proof'}
    assert condition['edge'] == 'fallthrough'
    assert all(type(condition[k]) is int for k in ('site', 'successor', 'slow_path', 'stub'))
    assert context['scope'] in ('initial_stack_check_fast_path', 'entry_prefix', 'entry_result_use') and graph['format'] >= 18
    offset = graph['receiver_metadata']['stack_limit_offset']
    assert type(offset) is int and offset == audit.get('stack_limit_offset') and 0 <= offset <= 32760 and offset % 8 == 0
    assert graph['profile']['thread_register'] == 'x26'
    start = context['payload']
    words = {ins.address: int.from_bytes(ins.bytes, 'little') for ins in instructions}
    assert 6 <= len(words) <= 16384 and sorted(words) == list(range(start, start+len(words)*4, 4))
    site, fast, slow, stub = (condition[k] for k in ('site', 'successor', 'slow_path', 'stub'))
    assert site in words and 2 <= (site-start)//4 and (not initial or (site-start)//4 < 32) and fast == site+4 and slow > fast and slow+4 in words
    assert condition['proof'] == [site-8, site-4, site, slow, slow+4]
    load = words[site-8]
    target = load & 31
    assert target not in (15, 21, 22, 26, 27, 28, 29, 30, 31)
    # Plain unsigned-offset LDR X or signed-offset LDUR X; neither writes its base.
    if load & 0xffc00000 == 0xf9400000:
        displacement = ((load >> 10) & 0xfff)*8
    else:
        assert load & 0xffe00c00 == 0xf8400000
        displacement = (load >> 12) & 0x1ff
        if displacement & 0x100: displacement -= 0x200
    assert (load >> 5) & 31 == 26 and displacement == offset
    assert words[site-4] == 0xeb00001f | (target << 16) | (15 << 5), 'Not a plain CMP X15, Xlimit'
    assert words[site] & 0xff00001f == 0x54000009 and branch(words[site], site)[1] == slow
    assert words[slow] & 0xfc000000 == 0x94000000 and branch(words[slow], slow)[1] == stub
    assert dict(graph['receiver_metadata']['frame_preserving_calls']).get(stub) == 'stack_overflow_without_fpu'
    assert dict(audit.get('frame_preserving_calls', [])).get(stub) == 'stack_overflow_without_fpu'
    assert words[slow+4] & 0xfc000000 == 0x14000000 and branch(words[slow+4], slow+4)[1] == fast
    previous = slow-4
    for _ in range(3):
        if words.get(previous) != 0xd503201f: break
        previous -= 4
    word = words.get(previous, 0)
    assert (word & 0xfffffc1f == 0xd65f0000 or word & 0xffe0001f in (0xd4200000, 0xd4400000)
            or word & 0xfc000000 == 0x14000000), 'Slow block admits a fallthrough'
    assert not initial or not any(start < pc <= site or pc in (fast, slow, slow+4) for pc in external)
    for pc, word in words.items():
        transfer = branch(word, pc)
        if initial and pc < site:
            assert transfer is None and word & 0xfffffc1f != 0xd65f0000 and word & 0xffe0001f not in (0xd4200000, 0xd4400000)
        if transfer:
            kind, target = transfer
            assert kind != 'indirect_jump'
            if isinstance(target, int):
                assert not initial or not start <= target <= site
                assert target != fast or pc == slow+4
                assert target != slow or pc == site
                assert target != slow+4
    return condition
