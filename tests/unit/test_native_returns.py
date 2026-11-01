"""Authored native identities and original-word normal-return controls."""
import copy
import unittest

import test_spill_certificates as spill_fixtures
from check_native_returns import check_native_returns
from check_receiver_analysis import check_receivers


class NativeReturns(unittest.TestCase):
    def setUp(self):
        fixture = spill_fixtures.SpillCertificates(); fixture.setUp()
        self.fixture = fixture
        self.graph = copy.deepcopy(fixture.graph)
        self.audit = copy.deepcopy(fixture.audit)
        self.raw = fixture.raw[:24] + (0xaa0003e2).to_bytes(4, 'little') + fixture.raw[28:]  # MOV x2,x0.
        self.graph['format'] = 23
        self.graph['nodes'].append({'start': 0x5000, 'end': 0x5004, 'names': []})
        metadata = self.graph['receiver_metadata']
        metadata.update(allocation_returns=[], word_return_register='x0', stack_limit_offset=None, entries=[0x2000, 0x2004, 0x3000, 0x5000],
                        native_return_classes=[[0x5000, 2, 'allocate_one_byte_string']])
        self.audit.update(predefined_allocations=[], word_return_register='x0',
                          native_return_sdk=[[17, 2, 'Internal_allocateOneByteString', 'allocate_one_byte_string'],
                                             [23, 3, 'Internal_allocateTwoByteString', 'allocate_two_byte_string']],
                          native_return_identities=[{'entry': 0x5000, 'code_entry': 0x5000, 'payload': 0x5000, 'end': 0x5004,
                              'is_native': True, 'owns_code': True, 'recognized_kind': 17,
                              'native_name': 'Internal_allocateOneByteString', 'library_uri': 'dart:_internal'}])
        self.graph['edges'][0]['native_return'] = {'callee': 0x5000, 'class_id': 2, 'register': 'x0',
            'contract': 'allocate_one_byte_string', 'condition': 'normal_return', 'basis': 'matched_sdk_native_identity'}
        self.graph['dispatch_table']['entries'].append(0x3000)
        self.graph['edges'][1]['static_dispatch'].update(index=2, table_index=2, snapshot_target=0x3000)
        block = self.graph['receiver_certificates'][0]['blocks'][1]
        block['spills'] = []
        block['facts'].append([0, 3, '0x2', '0x0', '0x0'])

    def read(self, address, length):
        assert 0x1000 <= address and address + length <= 0x1000 + len(self.raw)
        return self.raw[address-0x1000:address-0x1000+length]

    def check(self):
        return check_receivers(self.graph, self.read,
            lambda raw, address: list(self.fixture.decoder.disasm(raw, address)), self.audit)

    def test_normal_return_reaches_dispatch_without_frame_effect(self):
        report = self.check()
        self.assertEqual(report['receiver_claims_checked'], 1)
        self.assertEqual(report['native_return_contracts_checked'], 1)
        self.assertEqual(report['native_return_calls_checked'], 1)

    def test_two_byte_kind_uses_its_separate_sdk_class(self):
        self.graph['receiver_metadata']['native_return_classes'] = [[0x5000, 3, 'allocate_two_byte_string']]
        self.audit['native_return_identities'][0].update(recognized_kind=23, native_name='Internal_allocateTwoByteString')
        self.graph['edges'][0]['native_return'].update(class_id=3, contract='allocate_two_byte_string')
        self.assertEqual(check_native_returns(self.graph, self.read, self.audit), ({0x5000: 3}, 1))

    def test_mismatched_or_missing_identity_is_rejected(self):
        for key, value in [('recognized_kind', 23), ('native_name', 'Internal_allocateTwoByteString'),
                           ('library_uri', 'package:fixture/main.dart'), ('is_native', False), ('owns_code', False),
                           ('code_entry', 0x5004), ('payload', 0x4ffc), ('end', 0x5008), ('entry', True)]:
            with self.subTest(key=key):
                self.setUp(); self.audit['native_return_identities'][0][key] = value
                with self.assertRaises(AssertionError): self.check()
        self.setUp(); self.audit['native_return_identities'] = []
        with self.assertRaises(AssertionError): self.check()

    def test_conflicting_alias_cannot_be_hidden_by_a_good_alias(self):
        original = copy.deepcopy(self.audit['native_return_identities'][0])
        bad = dict(original, owns_code=False)
        for rows in ([original, bad], [bad, original], [original, bad, original]):
            with self.subTest(rows=rows):
                self.audit['native_return_identities'] = rows
                with self.assertRaises(AssertionError): self.check()

    def test_forged_claim_schema_and_original_call_fail(self):
        for key, value in [('callee', 0x5004), ('class_id', True), ('register', 'x1'),
                           ('contract', 'allocate_two_byte_string'), ('condition', 'always'), ('basis', 'function_name')]:
            with self.subTest(key=key):
                self.setUp(); self.graph['edges'][0]['native_return'][key] = value
                with self.assertRaises(AssertionError): self.check()
        self.setUp(); self.raw = self.raw[:20] + (0x94000ffc).to_bytes(4, 'little') + self.raw[24:]
        with self.assertRaises(AssertionError): self.check()

    def test_return_contract_does_not_preserve_a_caller_spill(self):
        self.raw = self.fixture.raw
        self.graph['edges'][1]['static_dispatch'].update(index=1, table_index=1, snapshot_target=0x2004)
        self.graph['receiver_certificates'][0]['blocks'][1]['spills'] = [[-24, 1]]
        with self.assertRaises(AssertionError): self.check()

    def test_allocator_effect_overlap_wrong_abi_and_old_format_fail(self):
        for defect in ('overlap', 'abi', 'old-format', 'missing-claim', 'duplicate-contract', 'sdk-class'):
            with self.subTest(defect=defect):
                self.setUp()
                if defect == 'overlap': self.graph['receiver_metadata']['allocation_returns'] = [[0x5000, 2]]
                elif defect == 'abi': self.audit['word_return_register'] = 'x1'
                elif defect == 'old-format': self.graph['format'] = 22
                elif defect == 'missing-claim': self.graph['edges'][0].pop('native_return')
                elif defect == 'duplicate-contract': self.graph['receiver_metadata']['native_return_classes'] *= 2
                else: self.audit['native_return_sdk'][0][1] = True
                with self.assertRaises(AssertionError): self.check()


if __name__ == '__main__':
    unittest.main()
