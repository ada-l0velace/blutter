"""Navigation shape, annotation scope and independent original-byte replay controls."""
import copy
import io
import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
from captured_field_values import SCOPE, note, replay, validate_structure, check_stream


class CapturedFieldsTests(unittest.TestCase):
    def setUp(self):
        self.g = dict(captured_field_work=dict(limit=200000, region_limit=64, context_limit=4096, map_limit=4096,
            steps=4, remaining=199996, complete=True), captured_field_stack_maps=[dict(payload=0x1000,site=0x100c,available=True,spill_slots=16,register_slots=None,objects=[-16])],
            receiver_metadata=dict(allocation_returns=[[0x2000,7]]),
            async_field_contexts=[dict(payload=0x1000, seed=0x1000, source_await=0xffc, basis='await_delivery',
                class_id=7, accesses=[dict(site=0x1000, register=1, base=0, bytes=4, offset=8, access='read')])],
            async_field_work=dict(supported=True), saved_reference_abi=dict(supported=True, first_local_offset=-8),
            future_binding_abi=dict(supported=True, suspend_state_offset=-8), saved_reference_frames=[dict(payload=0x1000, status='matched_async_frame', points=[[pc,-128,True] for pc in range(0x1000,0x1018,4)])],
            captured_field_contexts=[dict(context=0, access=0, scope=SCOPE, status='control_boundary', steps=4,
                reloads=[dict(site=0x1010, register=3, store=0x1008, slot=-16, call=0x100c, target=0x2000)])])

    def test_structure(self):
        self.assertEqual(len(validate_structure(self.g)), 1)

    def test_scope_and_work_forgery(self):
        for defect in ('scope', 'work', 'frame', 'seed', 'duplicate', 'missing'):
            with self.subTest(defect=defect):
                g = copy.deepcopy(self.g)
                c = g['captured_field_contexts'][0]
                if defect == 'scope':c['scope'] = 'unconditional'
                elif defect == 'work':g['captured_field_work']['steps'] += 1
                elif defect == 'frame':g['saved_reference_frames'][0]['status'] = 'frame_address_escapes'
                elif defect == 'seed':c['context'] = 8
                elif defect == 'duplicate':c['reloads'] *= 2
                else:g['captured_field_contexts'] = []
                with self.assertRaises((AssertionError, IndexError)):validate_structure(g)

    def test_comments(self):
        c = self.g['captured_field_contexts'][0]
        text = note(self.g, c, c['reloads'][0])
        lines = '// ' + text + '\n// 0x1010: ldur x3, [fp, #-16]\n'
        self.assertEqual(sum(check_stream(self.g, io.StringIO(lines)).values()), 1)
        for bad in (lines.replace('conditional:', 'unconditional:'), lines.replace('FP-16', 'FP-24'),
                    lines.replace('X3', 'X4'), '// 0x1010: ldur x3, [fp, #-16]\n', '// ' + text):
            with self.assertRaises(AssertionError):check_stream(self.g, io.StringIO(bad))

    def test_architectural_replay(self):
        import capstone
        md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
        md.detail = True
        words = [0xb8407001, 0x8b1c8021, 0xf81f03a1, 0x940003fd, 0xf85f03a3, 0xd65f03c0]
        def run(words=words, objects=(-16,), barriers=(), exact=True, allocations=(0x2000,)):
            insns = list(md.disasm(b''.join(w.to_bytes(4, 'little') for w in words), 0x1000))
            return replay(insns, self.g['async_field_contexts'][0]['accesses'][0],
                {i.address: (-128, exact) for i in insns}, set(barriers),
                {0x100c: dict(available=True, objects=objects, spill_slots=16)}, allocations, -8, -8, 'x28')
        self.assertEqual(run(), self.g['captured_field_contexts'][0]['reloads'])
        self.assertEqual(run(objects=()), [])
        self.assertEqual(run(barriers=(0x1010,)), [])
        self.assertEqual(run(allocations=()), [])
        changed = list(words)
        changed[2] = 0xb81f03a1 # narrow spill
        self.assertEqual(run(changed), [])
        changed = list(words)
        changed[1] = 0xd503201f # no reconstruction
        self.assertEqual(run(changed), [])


if __name__ == '__main__':unittest.main()
