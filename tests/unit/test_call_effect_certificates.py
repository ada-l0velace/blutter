"""Authored callee invariants; reject forged frame and native-call effects."""
import copy
import unittest

import test_spill_certificates as spill_fixture
from check_receiver_analysis import check_receivers


class CallEffectCertificates(unittest.TestCase):
    def setUp(self):
        self.fixture = spill_fixture.SpillCertificates()
        self.fixture.setUp()
        self.graph, self.audit = self.fixture.graph, self.fixture.audit
        self.graph['format'] = 9
        self.graph['profile']['pool_length'] = 32
        self.graph['nodes'].append({'start': 0x5000, 'end': 0x501c, 'names': []})
        self.graph['receiver_metadata']['entries'] = [0x2000, 0x2004, 0x5000]
        self.graph['receiver_metadata']['allocation_returns'] = []
        self.audit['predefined_allocations'] = []
        self.words = [0xa9bf79fd, 0xaa0f03fd, 0xd10041ef, 0xf90001ff,
                      0xaa1d03ef, 0xa8c179fd, 0xd65f03c0]
        seed = [[15, 1, 0], [27, 4, 0], [29, 2, 0], [30, 3, 0]]
        saved = [[-16, 2, 0], [-8, 3, 0]]
        pre_fp = [[15, 1, -16], [27, 4, 0], [29, 2, 0], [30, 3, 0]]
        framed = [[15, 1, -16], [27, 4, 0], [29, 1, -16], [30, 3, 0]]
        active = [[15, 1, -32], [27, 4, 0], [29, 1, -16], [30, 3, 0]]
        self.seed = seed
        self.graph['call_effects'] = [{'payload': 0x5000, 'depth': 1, 'states': copy.deepcopy([
            [0x5000, seed, []], [0x5004, pre_fp, saved], [0x5008, framed, saved],
            [0x500c, active, saved], [0x5010, active, saved], [0x5014, framed, saved],
            [0x5018, seed, []]])}]

    def check(self):
        code = b''.join(w.to_bytes(4, 'little') for w in self.words)
        def read(address, length):
            return {0x1000: self.fixture.raw, 0x5000: code}[address][:length]
        return check_receivers(self.graph, read, lambda raw, address: list(self.fixture.decoder.disasm(raw, address)), self.audit)

    def test_original_frame_only_callee_preserves_caller_class(self):
        result = self.check()
        self.assertEqual(result['receiver_claims_checked'], 1)
        self.assertEqual(result['call_effects_checked'], 1)

    def test_write_at_caller_entry_is_rejected(self):
        self.words[3] = 0xf90011ff  # STR xzr,[x15,#32]: exactly callee entry SP.
        with self.assertRaises(AssertionError):
            self.check()

    def test_forged_origins_saved_slots_and_missing_states_fail(self):
        original = copy.deepcopy(self.graph['call_effects'])
        for mutation in ('fp', 'slot', 'missing', 'seed', 'depth'):
            self.graph['call_effects'] = copy.deepcopy(original)
            certificate = self.graph['call_effects'][0]
            if mutation == 'fp':
                certificate['states'][2][1][2] = [29, 2, 0]
            elif mutation == 'slot':
                certificate['states'][1][2][0] = [-16, 3, 0]
            elif mutation == 'missing':
                del certificate['states'][3]
            elif mutation == 'seed':
                certificate['states'][0][1][0] = [15, 1, -16]
            else:
                certificate['depth'] = 9
            with self.subTest(mutation=mutation), self.assertRaises(AssertionError):
                self.check()

    def test_recursive_or_unknown_native_call_has_no_effect_contract(self):
        for instruction in (0x94000000, 0xd63f0120):  # BL self, BLR x9.
            self.words[3] = instruction
            with self.subTest(instruction=hex(instruction)), self.assertRaises(AssertionError):
                self.check()

    def test_modified_saved_return_is_rejected(self):
        self.words[3] = 0xf9000dff  # STR xzr,[x15,#24]: original saved LR.
        with self.assertRaises(AssertionError):
            self.check()

    def test_unpredictable_writeback_overlap_is_rejected(self):
        self.words[3] = 0xf81f8def  # STR x15,[x15,#-8]!: overlapping base/source.
        with self.assertRaises(AssertionError):
            self.check()

    def use_math_wrapper(self):
        self.words = [0xa9bf79fd, 0xaa0f03fd, 0x927cedef, 0x910001ff,
                      0xf9404350, 0xf9004750, 0xd63f0200, 0xd2800110,
                      0xf9004750, 0xf9404b50, 0xd140061f, 0xaa1d03ef, 0xa8c179fd, 0xd65f03c0]
        self.graph['nodes'][1]['end'] = 0x5038
        self.graph['receiver_metadata']['leaf_math_contract'] = [0x80, 0x88, 0x90, 8]
        self.audit['leaf_math_contract'] = [0x80, 0x88, 0x90, 8]
        self.graph['call_effects'] = [{'payload': 0x5000, 'depth': 1, 'states':
                                      [[0x5000, self.seed, []], [0x5034, self.seed, []]]}]

    def test_exact_reviewed_math_frame_preserves_caller_class(self):
        self.use_math_wrapper()
        self.assertEqual(self.check()['receiver_claims_checked'], 1)

    def test_partial_math_wrapper_or_changed_tls_fields_fail(self):
        self.use_math_wrapper()
        original = self.words[:]
        for position in (0, 4, 6, 8, 10, 12):
            self.words = original[:]
            self.words[position] = 0xd503201f
            with self.subTest(position=position), self.assertRaises(AssertionError):
                self.check()

    def test_math_contract_requires_separate_audit(self):
        self.use_math_wrapper()
        self.audit.pop('leaf_math_contract')
        with self.assertRaises(AssertionError):
            self.check()


if __name__ == '__main__':
    unittest.main()
