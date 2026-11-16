"""Container survival is distinct from argument roles and callee field use."""
import copy
import io
import unittest
import test_fresh_fields as fresh_fixture
from fresh_content_uses import SCOPE, validate_structure, replay, check_stream, check_contents
from query_fresh_contents import query, render


class FreshContentsTests(unittest.TestCase):
    def setUp(self):
        fixture = fresh_fixture.FreshFieldsTests('test_scope_and_bounds');fixture.setUp();self.g = fixture.g
        self.g.update(format=44, fresh_content_allocators=[], fresh_content_contexts=[dict(initialization=0,
            status='consumer_role_unproved', steps=2, transfer=0x101c, inputs=[], proof=[0x1014,0x1018,0x101c], scope=SCOPE)],
            fresh_content_work=dict(limit=200000, region_limit=128, context_limit=4096, steps=2, remaining=199998, complete=True))

    def test_unproved_role_is_diagnostic_only(self):
        validate_structure(self.g)
        rows = query(self.g, 0x1014)
        self.assertEqual(rows[0]['inputs'], [])
        self.assertIn('consumer_role_unproved', render(rows))

    def test_missing_seed_is_not_a_complete_result(self):
        self.g['fresh_content_contexts'] = []
        self.g['fresh_content_work'].update(steps=0, remaining=200000)
        with self.assertRaises(AssertionError):validate_structure(self.g)

    def test_scope_and_work_forgery(self):
        for key, value in [('scope', 'persistent_value'), ('steps', 129), ('inputs', [0]), ('initialization', 9), ('transfer', None)]:
            with self.subTest(key=key):
                g = copy.deepcopy(self.g);g['fresh_content_contexts'][0][key] = value
                with self.assertRaises((AssertionError, IndexError, KeyError)):validate_structure(g)

    def test_unproved_role_cannot_print_input_comment(self):
        with self.assertRaises(AssertionError):
            check_stream(self.g, io.StringIO('// container input origin: fabricated\n// 0x101c: b 0x2000\n'))

    def test_old_format_has_no_new_contract(self):
        self.g['format'] = 43
        self.assertEqual(check_contents(self.g, {}, lambda *_: self.fail('Old format read')), 0)

    def test_original_store_replayed(self):
        import capstone
        g = self.g;g['call_input_abi'] = dict(supported=True, word_bytes=8)
        g.update(call_input_shapes=[], stub_input_contracts=[], async_contracts=[dict(entry=0x2000, operation='complete_value')],
            edges=[dict(site=0x101c, source=0x1000, kind='jump', target=0x2000)],
            call_input_origins=[dict(site=0x101c, payload=0x1000, role='completion_operand', index=None, register=0, sp_offset=None)])
        g['receiver_metadata']['preserved_call_registers'] = []
        c = g['fresh_content_contexts'][0];c.update(status='matched_container_input', inputs=[0])
        md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN);md.detail = True
        words = [0xd503201f]*5 + [0xb8007003, 0xd503201f, 0x140003f9]
        def decode():return list(md.disasm(b''.join(w.to_bytes(4, 'little') for w in words), 0x1000))
        replay(g, c, decode(), set())
        words[6] = 0xb8007004
        with self.assertRaises(AssertionError):replay(g, c, decode(), set())


if __name__ == '__main__':unittest.main()
