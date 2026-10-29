"""Authored full-word input aliases and caller-specific result certificates."""
import copy
import unittest

import test_spill_certificates as spill_fixture
from check_call_effects import check_call_effects
from check_receiver_analysis import check_receivers


class ReturnForwarding(unittest.TestCase):
    def setUp(self):
        self.fixture = spill_fixture.SpillCertificates()
        self.fixture.setUp()
        self.seed = [[15, 1, 0], [27, 4, 0], [29, 2, 0], [30, 3, 0]]
        self.effect = {'payload': 0x5000, 'depth': 1, 'return_input': 0,
                       'states': [[0x5000, copy.deepcopy(self.seed), []],
                                  [0x5004, [[0, 9, 0]] + copy.deepcopy(self.seed), []]]}
        self.code = (0xf94001e0).to_bytes(4, 'little') + (0xd65f03c0).to_bytes(4, 'little')
        self.graph = copy.deepcopy(self.fixture.graph)
        self.graph['format'] = 12
        self.graph['nodes'].append({'start': 0x5000, 'end': 0x5008, 'names': []})
        self.graph['profile']['pool_length'] = 32
        self.graph['receiver_metadata'].update(word_return_register='x0', allocation_returns=[], entries=[0x2000, 0x2004, 0x5000])
        self.graph['call_effects'] = [self.effect]
        self.audit = dict(self.fixture.audit, predefined_allocations=[], word_return_register='x0')

    def read(self, address, length):
        return {0x1000: self.fixture.raw, 0x5000: self.code}[address][:length]

    def decode(self, raw, address):
        return list(self.fixture.decoder.disasm(raw, address))

    def check_effect(self):
        return check_call_effects(self.graph, self.read, self.decode, set(), self.audit)

    def test_exact_input_alias_is_independently_checked(self):
        effects, words = self.check_effect()
        self.assertEqual(effects, {0x5000})
        self.assertEqual(words, 2)

    def test_forged_slot_and_abi_do_not_pass(self):
        for defect in ('offset', 'unaligned', 'outside', 'boolean', 'audit', 'abi', 'old-format'):
            with self.subTest(defect=defect):
                self.setUp()
                if defect in ('offset', 'unaligned', 'outside', 'boolean'):
                    self.effect['return_input'] = {'offset': 8, 'unaligned': 1, 'outside': 256, 'boolean': False}[defect]
                elif defect == 'audit': self.audit.pop('word_return_register')
                elif defect == 'abi': self.graph['receiver_metadata']['word_return_register'] = 'x1'
                else: self.graph['format'] = 11
                with self.assertRaises(AssertionError): self.check_effect()

    def test_changed_original_load_or_invented_entry_alias_fails(self):
        for defect in ('changed-slot', 'narrow', 'seed', 'missing'):
            with self.subTest(defect=defect):
                self.setUp()
                if defect in ('changed-slot', 'narrow'):
                    word = 0xf94005e0 if defect == 'changed-slot' else 0xb94001e0
                    self.code = word.to_bytes(4, 'little') + self.code[4:]
                elif defect == 'seed': self.effect['states'][0][1].insert(0, [0, 9, 0])
                else: self.effect['states'].pop()
                with self.assertRaises(AssertionError): self.check_effect()

    def caller(self):
        raw = bytearray(self.fixture.raw)
        raw[16:20] = (0xf90001e0).to_bytes(4, 'little')  # STR x0,[x15].
        raw[24:28] = (0xaa0003e2).to_bytes(4, 'little')  # MOV x2,x0.
        self.fixture.raw = bytes(raw)
        second = self.graph['receiver_certificates'][0]['blocks'][1]
        second['facts'].append([0, 3, '0x1', '0x0', '0x0'])
        second['spills'] = [[-48, 1]]
        self.graph['edges'][0]['forwarded_return'] = {
            'callee': 0x5000, 'input_sp_offset': 0, 'register': 'x0', 'class_id': 1,
            'proof': list(range(0x1000, 0x1018, 4))}

    def test_returned_class_reaches_later_dispatch(self):
        self.caller()
        report = check_receivers(self.graph, self.read, self.decode, self.audit)
        self.assertEqual(report['receiver_claims_checked'], 1)
        self.assertEqual(report['forwarded_return_calls_checked'], 1)
        self.assertEqual(report['forwarded_input_summaries_checked'], 1)

    def test_forged_caller_class_target_offset_and_missing_proof_fail(self):
        for defect in ('class', 'boolean-class', 'target', 'offset', 'boolean-offset', 'register', 'proof', 'certificate'):
            with self.subTest(defect=defect):
                self.setUp()
                self.caller()
                claim = self.graph['edges'][0]['forwarded_return']
                if defect == 'class': claim['class_id'] = 2
                elif defect == 'boolean-class': claim['class_id'] = True
                elif defect == 'target': claim['callee'] = 0x5004
                elif defect == 'offset': claim['input_sp_offset'] = 8
                elif defect == 'boolean-offset': claim['input_sp_offset'] = False
                elif defect == 'register': claim['register'] = 'x1'
                elif defect == 'proof': claim['proof'] = [0x1000]
                else: self.graph['call_effects'] = []
                with self.assertRaises(AssertionError): check_receivers(self.graph, self.read, self.decode, self.audit)


if __name__ == '__main__':
    unittest.main()
