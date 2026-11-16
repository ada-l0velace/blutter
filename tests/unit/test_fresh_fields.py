"""First-write scopes, destination bounds and independent value/allocation replay."""
import copy
import io
import unittest
import test_captured_fields as captured_fixture
from fresh_field_initializations import SCOPE, validate_structure, replay, check_stream, note


class FreshFieldsTests(unittest.TestCase):
    def setUp(self):
        fixture = captured_fixture.CapturedFieldsTests('test_structure');fixture.setUp();self.g = fixture.g
        self.g['receiver_metadata'].update(allocation_result_register='x0', allocation_body_bounds=[[0x2000, 7, 31]], array_body_contract=[])
        self.g['fresh_field_layouts'] = [dict(class_id=7, kind='instance', header=8, end=32, tag=1, slot_bytes=4, excluded=[16], unboxed=[24,28])]
        self.g['fresh_field_contexts'] = [dict(capture=0, reload=0, class_id=7, kind='instance_field', status='matched_initialization', steps=2,
            length_steps=0, length=None, length_source=None, scope=SCOPE, write=dict(site=0x1014, base=0, register=3, bytes=4, offset=8, index=None))]
        self.g['fresh_field_work'] = dict(limit=200000, region_limit=64, context_limit=4096, steps=2, remaining=199998, complete=True)

    def test_scope_and_bounds(self):
        self.assertEqual(len(validate_structure(self.g)), 1)
        for defect in ('scope', 'field', 'class', 'parent', 'budget', 'duplicate'):
            with self.subTest(defect=defect):
                bad = copy.deepcopy(self.g);row = bad['fresh_field_contexts'][0]
                if defect == 'scope':row['scope'] = 'persistent_contents'
                elif defect == 'field':row['write']['offset'] = 16
                elif defect == 'class':row['class_id'] += 1
                elif defect == 'parent':row['capture'] = 99
                elif defect == 'budget':bad['fresh_field_work']['steps'] += 1
                else:bad['fresh_field_contexts'] *= 2
                with self.assertRaises((AssertionError, KeyError, IndexError)):validate_structure(bad)

    def test_comment_attachment(self):
        c = self.g['fresh_field_contexts'][0]
        text = '// ' + note(self.g, c) + '\n// 0x1014: stur w3, [x0, #7]\n'
        self.assertEqual(sum(check_stream(self.g, io.StringIO(text)).values()), 1)
        for bad in (text.replace('first explicit write only', 'persistent contents'), text.replace('0x1014:', '0x1018:'), text.replace('slot 0x8 of class', 'slot 0xc of class')):
            if bad == text:continue
            with self.assertRaises(AssertionError):check_stream(self.g, io.StringIO(bad))

    def test_architectural_replay(self):
        import capstone
        md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN);md.detail = True
        words = [0xb8407001,0x8b1c8021,0xf81f03a1,0x940003fd,0xf85f03a3,0xb8007003,0xd65f03c0]
        reload = self.g['captured_field_contexts'][0]['reloads'][0]
        def run(words=words, barriers=()):
            insns = list(md.disasm(b''.join(w.to_bytes(4,'little') for w in words),0x1000))
            return replay(insns,reload,set(barriers),self.g['fresh_field_layouts'][0],None,None)
        self.assertEqual(run(),self.g['fresh_field_contexts'][0]['write'])
        self.assertIsNone(run(barriers=(0x1014,)))
        changed = list(words);changed[5] = 0xb8007004
        self.assertIsNone(run(changed))
        changed = list(words);changed.insert(5,0xb8007085)
        self.assertIsNone(run(changed))
        changed = list(words);changed[5] = 0xb8007000
        self.assertIsNone(run(changed))

    def test_unproved_write_query_is_refused(self):
        from query_fresh_fields import query
        with self.assertRaisesRegex(ValueError, 'No proven fresh initialization'):query(self.g,0x1010)


if __name__ == '__main__':unittest.main()
