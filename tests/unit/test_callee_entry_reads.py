"""Physical entry reads do not establish source parameter order or element use."""
import copy
import io
import unittest
import test_fresh_contents as content_fixture
from callee_entry_reads import LIMITS, validate_structure, replay_prefix, check_stream, note, check_entry_reads
from query_container_consumers import query, render


class CalleeEntryReadsTests(unittest.TestCase):
    def setUp(self):
        fixture = content_fixture.FreshContentsTests();fixture.setUp();self.g = fixture.g
        self.g.update(format=45, nodes=[dict(start=0x1000, end=0x1020), dict(start=0x2000, end=0x2008)],
            edges=[dict(site=0x101c, source=0x1000, kind='call', target=0x2000)],
            callee_entry_read_contracts=[dict(entry=0x2000, end=0x2008, stop='call_or_return',
                steps=2, decoded=2, prefix=[0x2000], reads=[dict(site=0x2000, entry_sp_offset=0, register=1, part=0, bytes=8)], guard=None)],
            container_entry_read_links=[dict(context=0, contract=0, read=0, scope='conditional_callee_entry_read')],
            callee_entry_read_work=dict(LIMITS, steps=4, remaining=199996, bytes=8, complete=True))

    def decode(self, words):
        import capstone as cs
        md = cs.Cs(cs.CS_ARCH_ARM64, cs.CS_MODE_LITTLE_ENDIAN);md.detail = True
        return list(md.disasm(b''.join(w.to_bytes(4, 'little') for w in words), 0x2000))

    def test_physical_scope_and_unknown_source_position(self):
        validate_structure(self.g)
        text = render(query(self.g, 0x101c))
        self.assertIn('callee entry SP+0x0', text)
        self.assertIn('source parameter position/type and later element/field use unknown', text)
        self.assertNotIn('supplied input[0]', text)

    def test_prefix_replayed_against_original_load(self):
        c = self.g['callee_entry_read_contracts'][0]
        replay_prefix(c, self.decode([0xf94001e1, 0xd65f03c0]), self.g, {})
        for word in [0xf94005e1, 0xb94001e1, 0xf94001e2]:
            with self.subTest(word=word), self.assertRaises(AssertionError):
                replay_prefix(c, self.decode([word, 0xd65f03c0]), self.g, {})

    def test_unsafe_prefix_cannot_be_certified(self):
        c = self.g['callee_entry_read_contracts'][0]
        c.update(end=0x200c, decoded=3, steps=3, prefix=[0x2000, 0x2004])
        c['reads'][0]['site'] = 0x2004
        for word in [0xf90001e2, 0xf9000082, 0x94000040, 0x14000001]:
            with self.subTest(word=word), self.assertRaises(AssertionError):
                replay_prefix(c, self.decode([word, 0xf94001e1, 0xd65f03c0]), self.g, {})

    def test_private_frame_store_is_safe(self):
        c = self.g['callee_entry_read_contracts'][0]
        words = [0xa9bf79fd, 0xaa0f03fd, 0xd10081ef, 0xf90001e2, 0xf9400ba1, 0xd65f03c0]
        c.update(end=0x2018, decoded=6, steps=6, prefix=list(range(0x2000, 0x2014, 4)))
        c['reads'][0]['site'] = 0x2010
        replay_prefix(c, self.decode(words), self.g, {})

    def test_pair_uses_preinstruction_base(self):
        c = self.g['callee_entry_read_contracts'][0]
        c.update(end=0x200c, decoded=3, steps=3, prefix=[0x2000, 0x2004], reads=[
            dict(site=0x2004, entry_sp_offset=0, register=3, part=0, bytes=8),
            dict(site=0x2004, entry_sp_offset=8, register=2, part=1, bytes=8)])
        replay_prefix(c, self.decode([0xaa0f03e3, 0xa9400863, 0xd65f03c0]), self.g, {})

    def test_narrow_coordinate_copy_is_not_identity(self):
        c = self.g['callee_entry_read_contracts'][0]
        c.update(end=0x2010, decoded=4, steps=4, prefix=[0x2000, 0x2004, 0x2008])
        c['reads'][0]['site'] = 0x2008
        with self.assertRaises(AssertionError):
            replay_prefix(c, self.decode([0xaa0f03e3, 0x2a0303e3, 0xf9400061, 0xd65f03c0]), self.g, {})

    def test_source_scope_or_negative_index_refused(self):
        for key, value in [('context', -1), ('contract', -1), ('read', -1), ('scope', 'formal_parameter')]:
            g = copy.deepcopy(self.g);g['container_entry_read_links'][0][key] = value
            with self.subTest(key=key), self.assertRaises(AssertionError):validate_structure(g)

    def test_duplicate_link_refused(self):
        self.g['container_entry_read_links'] *= 2
        with self.assertRaises(AssertionError):validate_structure(self.g)

    def test_interior_or_jump_target_refused(self):
        for key, value in [('target', 0x2004), ('kind', 'jump')]:
            g = copy.deepcopy(self.g);g['edges'][0][key] = value
            with self.subTest(key=key), self.assertRaises(AssertionError):validate_structure(g)

    def test_work_budget_cannot_be_hidden(self):
        for key in ('steps', 'bytes', 'limit', 'prefix_limit'):
            g = copy.deepcopy(self.g);g['callee_entry_read_work'][key] += 1
            with self.subTest(key=key), self.assertRaises(AssertionError):validate_structure(g)

    def test_prefix_omission_refused(self):
        self.g['callee_entry_read_contracts'][0]['prefix'] = []
        with self.assertRaises(AssertionError):validate_structure(self.g)

    def test_comment_exact_and_at_transfer(self):
        l = self.g['container_entry_read_links'][0]
        text = '// ' + note(self.g, l) + '\n// 0x101c: bl 0x2000\n'
        self.assertEqual(sum(check_stream(self.g, io.StringIO(text)).values()), 1)
        for bad in [text + text, text.replace('0x101c:', '0x1020:'), text.replace('SP+0x0', 'SP+0x8')]:
            with self.subTest(bad=bad), self.assertRaises(AssertionError):check_stream(self.g, io.StringIO(bad))

    def test_absent_role_is_explicit(self):
        self.g['container_entry_read_links'] = []
        self.assertIn('No role-proven', render(query(self.g, 0x101c)))

    def test_old_format_skips_new_phase(self):
        self.g['format'] = 44
        self.assertEqual(check_entry_reads(self.g, {}, lambda *_: self.fail('Old format read')), 0)


if __name__ == '__main__':unittest.main()
