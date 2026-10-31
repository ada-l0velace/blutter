"""Authored array producer certificates and adversarial proof controls."""
import copy
import unittest

import test_spill_certificates as fixture
from check_receiver_analysis import check_receivers


class ArrayCertificates(unittest.TestCase):
    def setUp(self):
        self.fixture = fixture.SpillCertificates()
        self.fixture.setUp()
        # MOV x2,#4; BL allocator; LDR x3,[PP,#40]; STUR w3,[x0,#15];
        # STR x0,[SP]; BL consumer; RET. All addresses/layouts are synthetic.
        self.words = [0xd2800082, 0x940013ff, 0xf9401763, 0xb800f003,
                      0xf90001e0, 0x94000bfb, 0xd65f03c0]
        self.graph = copy.deepcopy(self.fixture.graph)
        self.graph.update(format=13, nodes=[{'start': 0x1000, 'end': 0x101c, 'names': []}],
                          call_effects=[], edges=[{'site': 0x1004, 'kind': 'call', 'target': 0x6000},
                                                  {'site': 0x1014, 'kind': 'call', 'target': 0x4000,
                                                   'stack_inputs': [{'sp_offset': 0, 'kind': 'heap_class', 'value': '0x2', 'proof': [0x1004, 0x1010]}],
                                                   'array_arguments': [{'sp_offset': 0, 'allocation': 0x1004, 'length': 2, 'elements': [[0, 1]],
                                                                        'proof': list(range(0x1000, 0x1018, 4))}]}])
        self.graph['receiver_metadata'].update(entries=[], pool_classes=[[3, 1]], allocation_returns=[[0x6000, 2]],
                                              array_body_contract=[0x6000, 2, 15, 4, 1], heap_bits_register='x28')
        self.audit = dict(self.fixture.audit, pool_heap_classes=[[3, 1]], class_allocations=[[0x6000, 2]],
                          array_body_contract=[0x6000, 2, 15, 4, 1], heap_bits_register='x28')
        seed = [[15, 8, '0x0', '0x0', '0x0'], [21, 6, '0x0', '0x0', '0x0'],
                [22, 3, '0x1', '0x0', '0x0'], [26, 9, '0x0', '0x0', '0x0'],
                [27, 5, '0x0', '0x0', '0x0'], [29, 8, '0x0', '0x1', '0x0']]
        def block(start, end, entry=False, allocated=False):
            return {'start': start, 'end': end, 'entry': entry, 'reachable': True,
                    'facts': ([[0, 3, '0x2', '0x0', '0x0']] if allocated else []) + copy.deepcopy(seed),
                    'compare': [], 'live_inputs': [], 'spills': [],
                    'fresh_array': {'allocation': 0x1004, 'length': 2} if allocated else None}
        self.graph['receiver_certificates'] = [{'payload': 0x1000, 'blocks': [block(0x1000, 0x1008, entry=True),
                                                                           block(0x1008, 0x1018, allocated=True), block(0x1018, 0x101c)]}]

    def check(self):
        raw = b''.join(word.to_bytes(4, 'little') for word in self.words)
        return check_receivers(self.graph, lambda address, size: raw[address-0x1000:address-0x1000+size],
                               lambda data, address: list(self.fixture.decoder.disasm(data, address)), self.audit)

    def test_partial_contents_are_checked(self):
        result = self.check()
        self.assertEqual(result['array_argument_calls_checked'], 1)
        self.assertEqual(result['array_argument_elements_checked'], 1)

    def test_forged_array_arguments_fail(self):
        for defect in ('class', 'unknown-slot', 'duplicate-slot', 'duplicate-edge', 'boolean-index', 'offset', 'length', 'allocation', 'proof'):
            with self.subTest(defect=defect):
                self.setUp()
                arg = self.graph['edges'][1]['array_arguments'][0]
                if defect == 'class': arg['elements'] = [[0, 2]]
                elif defect == 'unknown-slot': arg['elements'] = [[1, 1]]
                elif defect == 'duplicate-slot': arg['elements'] *= 2
                elif defect == 'duplicate-edge':
                    self.graph['edges'].append({'site': 0x1014, 'kind': 'call', 'target': 0x4000, 'array_arguments': [copy.deepcopy(arg)]})
                elif defect == 'boolean-index': arg['elements'] = [[False, 1]]
                elif defect == 'offset': arg['sp_offset'] = 8
                elif defect == 'length': arg['length'] = 3
                elif defect == 'allocation': arg['allocation'] = 0x1000
                else: arg['proof'] = [0x1004]
                with self.assertRaises(AssertionError): self.check()

    def test_forged_handoff_and_missing_audits_fail(self):
        for defect in ('seed', 'seed-length', 'entry-seed', 'audit', 'heap-audit', 'legacy', 'missing-certificate'):
            with self.subTest(defect=defect):
                self.setUp()
                blocks = self.graph['receiver_certificates'][0]['blocks']
                if defect == 'seed': blocks[1]['fresh_array'] = None
                elif defect == 'seed-length': blocks[1]['fresh_array']['length'] = 3
                elif defect == 'entry-seed': blocks[0]['fresh_array'] = dict(blocks[1]['fresh_array'])
                elif defect == 'audit': self.audit['array_body_contract'][3] = 8
                elif defect == 'heap-audit': self.audit.pop('heap_bits_register')
                elif defect == 'legacy': self.graph['format'] = 12
                else: self.graph['receiver_certificates'] = []
                with self.assertRaises(AssertionError): self.check()

    def test_changed_original_length_and_store_fail(self):
        for word_index, replacement in [(0, 0xd28000c2), (2, 0xf9401f63), (3, 0xb800f009)]:
            with self.subTest(word=word_index):
                self.setUp()
                self.words[word_index] = replacement
                with self.assertRaises(AssertionError): self.check()


if __name__ == '__main__':
    unittest.main()
