"""Authored invariant certificates and adversarial mutations; no app data."""
import copy
from pathlib import Path
import sys
import unittest

import capstone

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
from check_receiver_analysis import check_receivers


class ReceiverCertificates(unittest.TestCase):
    def setUp(self):
        self.decoder = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
        self.decoder.detail = True
        # MOV x0,#1; LDR x30,[x21,x0,LSL#3]; BLR x30.
        self.raw = b''.join(w.to_bytes(4, 'little') for w in (0xd2800020, 0xf8607abe, 0xd63f03c0))
        self.graph = {
            'profile': {'pool_register': 'x27', 'dispatch_register': 'x21', 'pool_data_offset': 16, 'pool_slot_size': 8},
            'nodes': [{'start': 0x1000, 'end': 0x100c, 'names': []}],
            'edges': [{'site': 0x1008, 'target': None, 'static_dispatch': {'load': 0x1004, 'index': 1, 'table_index': 1,
                      'snapshot_target': 0x2004, 'proof': [0x1000, 0x1004]}}],
            'dispatch_table': {'origin': 0, 'entries': [0x2000, 0x2004]},
            'receiver_metadata': {'header_displacement': -1, 'class_id_shift': 8, 'class_id_bits': 16,
                                  'null_register': 'x22', 'null_class_id': 1, 'allocation_result_register': 'x0',
                                  'pool_classes': [], 'allocation_returns': [], 'entries': []},
            'receiver_certificates': [{'payload': 0x1000, 'blocks': [{'start': 0x1000, 'end': 0x100c, 'entry': True,
                                     'reachable': True, 'facts': [[21, 6, '0x0', '0x0', '0x0'],
                                         [22, 3, '0x1', '0x0', '0x0'], [27, 5, '0x0', '0x0', '0x0']], 'compare': []}]}]}

    def check(self, graph):
        return check_receivers(graph, lambda address, length: self.raw,
                               lambda raw, address: list(self.decoder.disasm(raw, address)),
                               {'pool_heap_classes': [], 'class_allocations': []})

    def test_valid_original_word_certificate(self):
        result = self.check(self.graph)
        self.assertEqual(result['receiver_claims_checked'], 1)
        self.assertEqual(result['receiver_incoming_edges_checked'], 1)

    def test_changed_claims_and_invented_seed_fact_fail(self):
        for key, value in [('index', 2), ('snapshot_target', 0x2000), ('table_index', 0), ('load', 0x1000), ('proof', [0x1000])]:
            graph = copy.deepcopy(self.graph)
            graph['edges'][0]['static_dispatch'][key] = value
            with self.subTest(key=key), self.assertRaises(AssertionError):
                self.check(graph)
        graph = copy.deepcopy(self.graph)
        graph['receiver_certificates'][0]['blocks'][0]['facts'].append([1, 3, '0x1', '0x0', '0x0'])
        with self.assertRaises(AssertionError):
            self.check(graph)

    def test_corrupted_control_flow_and_metadata_fail(self):
        for key, value in [('end', 0x1008), ('entry', False), ('reachable', False)]:
            graph = copy.deepcopy(self.graph)
            graph['receiver_certificates'][0]['blocks'][0][key] = value
            with self.subTest(key=key), self.assertRaises(AssertionError):
                self.check(graph)
        graph = copy.deepcopy(self.graph)
        graph['receiver_metadata']['pool_classes'] = [[0, 5]]
        with self.assertRaises(AssertionError):
            self.check(graph)


if __name__ == '__main__':
    unittest.main()
