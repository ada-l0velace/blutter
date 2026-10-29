"""Original GDT target proofs must justify any preserved caller spill."""
import unittest

import test_call_effect_certificates as callee_fixture


class IndirectEffectCertificates(unittest.TestCase):
    def setUp(self):
        self.fixture = callee_fixture.CallEffectCertificates()
        self.fixture.setUp()
        self.graph = self.fixture.graph
        self.graph['format'] = 10
        self.graph['nodes'][0]['end'] = 0x1034
        self.graph['dispatch_table']['entries'].append(0x5000)
        # Frame and spill, then MOV x3,#2; GDT load; BLR LR; reload and dispatch.
        words = [0xa9bf79fd, 0xaa0f03fd, 0xd10081ef, 0xf9401760, 0xf81f83a0,
                 0xd2800043, 0xf8637abe, 0xd63f03c0, 0xf85f83a2, 0xf85ff040,
                 0xd3485c00, 0xf8607abe, 0xd63f03c0]
        self.fixture.fixture.raw = b''.join(w.to_bytes(4, 'little') for w in words)
        blocks = self.graph['receiver_certificates'][0]['blocks']
        blocks[0]['end'] = 0x1020
        blocks[1].update(start=0x1020, end=0x1034)
        self.graph['edges'] = [
            {'site': 0x101c, 'source': 0x1000, 'kind': 'indirect_call', 'target': None,
             'static_dispatch': {'load': 0x1018, 'index': 2, 'table_index': 2,
                                 'snapshot_target': 0x5000, 'proof': [0x1014, 0x1018]}},
            {'site': 0x1030, 'source': 0x1000, 'kind': 'indirect_call', 'target': None,
             'static_dispatch': {'load': 0x102c, 'index': 1, 'table_index': 1,
                                 'snapshot_target': 0x2004, 'proof': list(range(0x1000, 0x1030, 4))}}]

    def test_callee_effect_and_pre_blr_lr_target_preserve_spill(self):
        self.assertEqual(self.fixture.check()['receiver_claims_checked'], 2)

    def test_known_target_without_verified_effect_does_not_preserve(self):
        self.graph['call_effects'] = []
        with self.assertRaises(AssertionError):
            self.fixture.check()

    def test_interior_target_cannot_borrow_entry_effect(self):
        self.graph['dispatch_table']['entries'][2] = 0x5004
        self.graph['edges'][0]['static_dispatch']['snapshot_target'] = 0x5004
        self.graph['receiver_metadata']['entries'] = [0x2000, 0x2004, 0x5004]
        with self.assertRaises(AssertionError):
            self.fixture.check()

    def test_narrow_target_load_cannot_keep_target_proof(self):
        raw = self.fixture.fixture.raw
        self.fixture.fixture.raw = raw[:24] + (0xb8637abe).to_bytes(4, 'little') + raw[28:]
        with self.assertRaises(AssertionError):
            self.fixture.check()

    def test_verified_effect_does_not_imply_working_register_preservation(self):
        self.graph['receiver_certificates'][0]['blocks'][1]['facts'].append([0, 3, '0x1', '0x0', '0x0'])
        with self.assertRaises(AssertionError):
            self.fixture.check()

    def test_new_preservation_rule_is_versioned(self):
        self.graph['format'] = 9
        with self.assertRaises(AssertionError):
            self.fixture.check()


if __name__ == '__main__':
    unittest.main()
