"""Authored SDK-stub identities and independent original-call controls."""
import unittest

import test_native_returns as native_fixtures
from check_receiver_analysis import check_receivers
from check_sdk_stub_returns import check_sdk_stub_returns


class SdkStubReturns(unittest.TestCase):
    def setUp(self):
        fixture = native_fixtures.NativeReturns()
        fixture.setUp()
        self.fixture = fixture
        self.graph, self.audit, self.raw = fixture.graph, fixture.audit, fixture.raw
        self.graph['format'] = 26
        self.graph['receiver_metadata']['native_return_classes'] = []
        self.graph['receiver_metadata']['sdk_stub_return_classes'] = [[0x5000, 2, 'allocate_growable_array']]
        self.graph['edges'][0]['native_return'] = None
        self.graph['edges'][0]['sdk_stub_return'] = {
            'callee': 0x5000, 'class_id': 2, 'register': 'x0', 'contract': 'allocate_growable_array',
            'condition': 'normal_return', 'basis': 'matched_sdk_stub_identity'}
        self.audit.update(sdk_stub_return_sdk=[['allocate_growable_array', 2]],
                          sdk_stub_return_reference={'entry': 0x5000, 'end': 0x5004, 'kind': 'allocate_growable_array'},
                          sdk_stub_return_identities=[{'entry': 0x5000, 'payload': 0x5000,
                                                       'end': 0x5004, 'kind': 'allocate_growable_array'}],
                          known_stubs=[{'entry': 0x5000, 'size': 4}])

    def read(self, address, length):
        if address == 0x5000 and length == 4:
            return bytes.fromhex('010000d4')
        if address == 0x6000 and length == 4:
            return bytes.fromhex('010000d4')
        assert 0x1000 <= address and address+length <= 0x1000+len(self.raw)
        return self.raw[address-0x1000:address-0x1000+length]

    def check(self):
        return check_receivers(self.graph, self.read,
                              lambda raw, address: list(self.fixture.fixture.decoder.disasm(raw, address)), self.audit)

    def test_normal_result_reaches_dispatch(self):
        result = self.check()
        self.assertEqual(result['sdk_stub_return_contracts_checked'], 1)
        self.assertEqual(result['sdk_stub_return_calls_checked'], 1)
        self.assertEqual(result['receiver_claims_checked'], 1)

    def test_identity_requires_original_payload_and_audited_stub(self):
        for key, value in [('entry', True), ('payload', 0x5004), ('end', 0x5008),
                           ('kind', 'name_guess'), ('entry', 0x5002)]:
            with self.subTest(key=key, value=value):
                self.setUp()
                self.audit['sdk_stub_return_identities'][0][key] = value
                with self.assertRaises(AssertionError):
                    self.check()
        for rows in ([], [{'entry': 0x5000, 'size': 8}]):
            with self.subTest(stubs=rows):
                self.setUp()
                self.audit['known_stubs'] = rows
                with self.assertRaises(AssertionError):
                    self.check()

    def test_conflicting_alias_is_never_revived(self):
        good = self.audit['sdk_stub_return_identities'][0]
        bad = dict(good, kind='unknown')
        for rows in ([good, bad], [bad, good], [good, bad, good]):
            with self.subTest(rows=rows):
                self.audit['sdk_stub_return_identities'] = rows
                with self.assertRaises(AssertionError):
                    self.check()

    def test_missing_duplicate_or_forged_contract_is_rejected(self):
        for rows in ([], [[0x5000, 3, 'allocate_growable_array']],
                     [[0x5000, True, 'allocate_growable_array']],
                     [[0x5000, 2, 'allocate_growable_array']]*2):
            with self.subTest(rows=rows):
                self.setUp()
                self.graph['receiver_metadata']['sdk_stub_return_classes'] = rows
                with self.assertRaises(AssertionError):
                    self.check()

    def test_claim_and_original_call_are_checked(self):
        for key, value in [('class_id', True), ('register', 'x1'), ('basis', 'function_name'),
                           ('condition', 'always'), ('callee', 0x5004), ('contract', 'allocate_one_byte_string')]:
            with self.subTest(key=key):
                self.setUp()
                self.graph['edges'][0]['sdk_stub_return'][key] = value
                with self.assertRaises(AssertionError):
                    self.check()
        self.setUp()
        self.raw = self.raw[:20] + (0x94000ffc).to_bytes(4, 'little') + self.raw[24:]
        with self.assertRaises(AssertionError):
            self.check()

    def test_missing_call_claim_wrong_abi_and_old_format_fail(self):
        for defect in ('claim', 'abi', 'format', 'class'):
            with self.subTest(defect=defect):
                self.setUp()
                if defect == 'claim':
                    self.graph['edges'][0]['sdk_stub_return'] = None
                elif defect == 'abi':
                    self.audit['word_return_register'] = self.graph['receiver_metadata']['word_return_register'] = 'x1'
                elif defect == 'format':
                    self.graph['format'] = 25
                else:
                    self.audit['sdk_stub_return_sdk'][0][1] = True
                with self.assertRaises(AssertionError):
                    self.check()

    def test_return_only_does_not_preserve_a_saved_object(self):
        self.raw = self.fixture.fixture.raw
        self.graph['receiver_certificates'][0]['blocks'][1]['spills'] = [[-24, 1]]
        with self.assertRaises(AssertionError):
            self.check()

    def test_overlapping_effect_or_summary_is_rejected(self):
        for field in ('allocation_returns', 'machine_return_classes', 'nonreturning_calls'):
            with self.subTest(field=field):
                self.setUp()
                self.graph['receiver_metadata'][field] = [[0x5000, 2]]
                with self.assertRaises(AssertionError):
                    check_sdk_stub_returns(self.graph, self.read, self.audit)

    def test_legacy_graph_without_contract_remains_supported(self):
        self.graph['format'] = 24
        self.graph['receiver_metadata'].pop('sdk_stub_return_classes')
        self.graph['edges'][0].pop('sdk_stub_return')
        self.assertEqual(check_sdk_stub_returns(self.graph, self.read, {}), ({}, 0))

    def test_exact_legacy_copy_uses_a_separate_sdk_reference(self):
        self.audit['sdk_stub_return_reference'].update(entry=0x6000, end=0x6004)
        self.audit['known_stubs'].append({'entry': 0x6000, 'size': 4})
        self.assertEqual(self.check()['sdk_stub_return_calls_checked'], 1)
        original = self.read
        def changed(address, length):
            return bytes.fromhex('c0035fd6') if address == 0x6000 else original(address, length)
        with self.assertRaises(AssertionError):
            check_sdk_stub_returns(self.graph, changed, self.audit)

    def test_missing_or_wrong_sdk_reference_is_rejected(self):
        for reference in (None, {'entry': True, 'end': 0x5004, 'kind': 'allocate_growable_array'},
                          {'entry': 0x5000, 'end': 0x5008, 'kind': 'allocate_growable_array'}):
            with self.subTest(reference=reference):
                self.audit['sdk_stub_return_reference'] = reference
                with self.assertRaises(AssertionError):
                    check_sdk_stub_returns(self.graph, self.read, self.audit)
