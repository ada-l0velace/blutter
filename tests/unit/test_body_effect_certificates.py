"""Authored object-body bounds and array-length proofs, independent of exporter."""
import copy
import unittest

import test_call_effect_certificates as callee_fixture


class BodyEffectCertificates(unittest.TestCase):
    def setUp(self):
        self.fixture = callee_fixture.CallEffectCertificates()
        self.fixture.setUp()
        self.graph, self.audit = self.fixture.graph, self.fixture.audit
        self.graph['format'] = 10
        self.graph['nodes'][1]['end'] = 0x5020
        metadata = self.graph['receiver_metadata']
        metadata['allocation_returns'] = [[0x2000, 1]]
        metadata['allocation_body_bounds'] = [[0x2000, 7, 31]]
        self.audit['class_allocations'] = [[0x2000, 1]]
        self.audit['allocation_body_bounds'] = [[0x2000, 7, 31]]
        self.fixture.words = [0xa9bf79fd, 0xaa0f03fd, 0xd10041ef, 0x97fff3fd,
                              0xf800701f, 0xaa1d03ef, 0xa8c179fd, 0xd65f03c0]
        self.saved = [[-16, 2, 0], [-8, 3, 0]]
        old = self.graph['call_effects'][0]['states']
        heap = [[0, 7, 0, 7, 31], [15, 1, -32], [27, 4, 0], [29, 1, -16]]
        frame = [[0, 7, 0, 7, 31], [15, 1, -16], [27, 4, 0], [29, 1, -16]]
        returned = [[0, 7, 0, 7, 31]] + self.fixture.seed
        self.graph['call_effects'][0]['states'] = copy.deepcopy(old[:4] + [
            [0x5010, heap, self.saved], [0x5014, heap, self.saved],
            [0x5018, frame, self.saved], [0x501c, returned, []]])

    def check(self):
        return self.fixture.check()

    def test_original_fixed_body_write_preserves_caller(self):
        self.assertEqual(self.check()['receiver_claims_checked'], 1)

    def test_header_and_overrun_writes_are_rejected(self):
        for displacement in (-1, 0, 6, 24, 31):
            self.fixture.words[4] = 0xf800001f | ((displacement & 511) << 12)
            with self.subTest(displacement=displacement), self.assertRaises(AssertionError):
                self.check()

    def test_bounds_require_matching_numerical_vm_audit(self):
        for rows in ([], [[0x2000, 7, 15]], [[0x2004, 7, 31]]):
            self.audit['allocation_body_bounds'] = rows
            with self.subTest(rows=rows), self.assertRaises(AssertionError):
                self.check()

    def test_forged_region_offset_and_limits_are_rejected(self):
        original = copy.deepcopy(self.graph['call_effects'])
        for field, value in ((2, 1), (3, 6), (3, 15), (4, 39), (4, 1 << 21)):
            self.graph['call_effects'] = copy.deepcopy(original)
            self.graph['call_effects'][0]['states'][4][1][0][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(AssertionError):
                self.check()

    def test_heap_fact_cannot_be_seeded_at_entry(self):
        self.graph['call_effects'][0]['states'][0][1].append([0, 7, 0, 7, 31])
        with self.assertRaises(AssertionError):
            self.check()

    def use_array(self):
        metadata = self.graph['receiver_metadata']
        metadata['allocation_returns'].append([0x6000, 2])
        metadata['array_body_contract'] = [0x6000, 2, 15, 4, 1]
        self.audit['predefined_allocations'] = [[0x6000, 2]]
        self.audit['array_body_contract'] = [0x6000, 2, 15, 4, 1]
        self.graph['nodes'][1]['end'] = 0x5024
        self.fixture.words = [0xa9bf79fd, 0xaa0f03fd, 0xd10041ef, 0xd2800082, 0x940003fc,
                              0xb801301f, 0xaa1d03ef, 0xa8c179fd, 0xd65f03c0]
        old = self.graph['call_effects'][0]['states'][:4]
        word = [[2, 8, 4], [15, 1, -32], [27, 4, 0], [29, 1, -16], [30, 3, 0]]
        heap = [[0, 7, 0, 15, 23], [15, 1, -32], [27, 4, 0], [29, 1, -16]]
        frame = [[0, 7, 0, 15, 23], [15, 1, -16], [27, 4, 0], [29, 1, -16]]
        returned = [[0, 7, 0, 15, 23]] + self.fixture.seed
        self.graph['call_effects'][0]['states'] = copy.deepcopy(old + [
            [0x5010, word, self.saved], [0x5014, heap, self.saved],
            [0x5018, heap, self.saved], [0x501c, frame, self.saved], [0x5020, returned, []]])

    def test_array_body_uses_tagged_length_and_element_size(self):
        self.use_array()
        self.assertEqual(self.check()['receiver_claims_checked'], 1)
        self.fixture.words[3] = 0x52800082  # MOV w2,#4 still zero-extends to the same Smi.
        self.assertEqual(self.check()['receiver_claims_checked'], 1)

    def test_array_metadata_and_length_do_not_imply_wider_body(self):
        self.use_array()
        for displacement in (7, 11, 20, 23):
            self.fixture.words[5] = 0xb800001f | (displacement << 12)
            with self.subTest(displacement=displacement), self.assertRaises(AssertionError):
                self.check()

    def test_changed_length_cannot_reuse_old_region(self):
        self.use_array()
        for length in (0, 2, 3, 6):
            self.fixture.words[3] = 0xd2800002 | (length << 5)
            self.graph['call_effects'][0]['states'][4][1][0][2] = length
            with self.subTest(length=length), self.assertRaises(AssertionError):
                self.check()

    def test_array_layout_requires_separate_audit(self):
        self.use_array()
        self.audit['array_body_contract'][3] = 8
        with self.assertRaises(AssertionError):
            self.check()

    def test_body_domain_is_not_accepted_in_older_format(self):
        self.graph['format'] = 9
        with self.assertRaises(AssertionError):
            self.check()


if __name__ == '__main__':
    unittest.main()
