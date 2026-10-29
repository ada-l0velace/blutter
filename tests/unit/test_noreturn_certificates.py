"""Authored normal-return path plus an independently audited throwing tail."""
import copy
import unittest

import test_call_effect_certificates as callee_fixture


class NonreturnCertificates(unittest.TestCase):
    def setUp(self):
        self.fixture = callee_fixture.CallEffectCertificates()
        self.fixture.setUp()
        self.graph, self.audit = self.fixture.graph, self.fixture.audit
        self.graph['format'] = 11
        self.graph['nodes'][1]['end'] = 0x5020
        self.graph['receiver_metadata']['nonreturning_calls'] = [[0xc000, 'range_error_without_fpu']]
        self.audit['nonreturning_calls'] = [[0xc000, 'range_error_without_fpu']]
        # Frame; CBZ x0,error; restore/RET; error: BL reviewed range-error entry.
        self.fixture.words = [0xa9bf79fd, 0xaa0f03fd, 0xd10041ef, 0xb4000080,
                              0xaa1d03ef, 0xa8c179fd, 0xd65f03c0, 0x94001bf9]
        states = self.graph['call_effects'][0]['states']
        states.append(copy.deepcopy(states[3]))
        states[-1][0] = 0x501c

    def test_returning_summary_can_exclude_verified_error_tail(self):
        result = self.fixture.check()
        self.assertEqual(result['receiver_claims_checked'], 1)
        self.assertEqual(result['nonreturning_call_inputs_checked'], 1)

    def test_nonreturn_requires_independent_audit(self):
        self.audit['nonreturning_calls'] = []
        with self.assertRaises(AssertionError):
            self.fixture.check()

    def test_nearby_entry_does_not_inherit_contract(self):
        self.graph['receiver_metadata']['nonreturning_calls'][0][0] = 0xc004
        self.audit['nonreturning_calls'][0][0] = 0xc004
        with self.assertRaises(AssertionError):
            self.fixture.check()

    def test_unknown_contract_name_is_rejected_even_if_audit_agrees(self):
        self.graph['receiver_metadata']['nonreturning_calls'][0][1] = 'name_says_throw'
        self.audit['nonreturning_calls'][0][1] = 'name_says_throw'
        with self.assertRaises(AssertionError):
            self.fixture.check()

    def test_old_format_cannot_hide_normal_fallthrough(self):
        self.graph['format'] = 10
        with self.assertRaises(AssertionError):
            self.fixture.check()

    def test_nonreturn_cannot_also_claim_allocation_return(self):
        self.graph['receiver_metadata']['allocation_returns'] = [[0xc000, 1]]
        self.audit['class_allocations'] = [[0xc000, 1]]
        with self.assertRaises(AssertionError):
            self.fixture.check()

    def test_nonreturn_entry_cannot_borrow_returning_summary(self):
        self.graph['call_effects'][0]['payload'] = 0xc000
        with self.assertRaises(AssertionError):
            self.fixture.check()

    def test_duplicate_contract_rows_are_rejected(self):
        self.graph['receiver_metadata']['nonreturning_calls'] *= 2
        with self.assertRaises(AssertionError):
            self.fixture.check()

    def make_dead_receiver_block(self):
        raw = self.fixture.fixture.raw
        self.fixture.fixture.raw = raw[:20] + (0x94002bfb).to_bytes(4, 'little') + raw[24:]
        self.graph['edges'][0]['target'] = 0xc000
        self.graph['edges'][1].pop('static_dispatch')
        self.graph['receiver_metadata']['entries'] = [0x2000, 0x2004]
        block = self.graph['receiver_certificates'][0]['blocks'][1]
        block.update(reachable=False, facts=[], compare=[], live_inputs=[], spills=[])

    def test_receiver_fallthrough_after_sink_is_unreachable(self):
        self.make_dead_receiver_block()
        self.assertEqual(self.fixture.check()['receiver_claims_checked'], 0)

    def test_receiver_cannot_claim_facts_after_sink(self):
        raw = self.fixture.fixture.raw
        self.fixture.fixture.raw = raw[:20] + (0x94002bfb).to_bytes(4, 'little') + raw[24:]
        self.graph['edges'][0]['target'] = 0xc000
        self.graph['receiver_metadata']['entries'] = [0x2000, 0x2004]
        with self.assertRaises(AssertionError):
            self.fixture.check()

    def test_returning_callee_still_requires_fallthrough(self):
        self.graph['edges'][1].pop('static_dispatch')
        block = self.graph['receiver_certificates'][0]['blocks'][1]
        block.update(reachable=False, facts=[], compare=[], live_inputs=[], spills=[])
        with self.assertRaises(AssertionError):
            self.fixture.check()


if __name__ == '__main__':
    unittest.main()
