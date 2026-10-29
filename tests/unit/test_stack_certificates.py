"""Authored stack certificates checked against independent original words."""
import copy
from pathlib import Path
import sys
import unittest

import capstone

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
from check_receiver_analysis import check_receivers


class StackCertificates(unittest.TestCase):
    def setUp(self):
        self.decoder = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
        self.decoder.detail = True
        # MOV x0,#1; STR x0,[x15]; BL 0x2000.
        self.raw = b''.join(w.to_bytes(4, 'little') for w in (0xd2800020, 0xf90001e0, 0x940003fe))
        self.graph = {
            'format': 5,
            'profile': {'pool_register': 'x27', 'thread_register': 'x26', 'dispatch_register': 'x21',
                        'pool_data_offset': 16, 'pool_slot_size': 8},
            'nodes': [{'start': 0x1000, 'end': 0x100c, 'names': []}],
            'edges': [{'site': 0x1008, 'target': 0x2000, 'stack_inputs': [
                {'sp_offset': 0, 'kind': 'word', 'value': '0x1', 'proof': [0x1000, 0x1004]}]}],
            'dispatch_table': {'origin': 0, 'entries': []},
            'receiver_metadata': {'header_displacement': -1, 'class_id_shift': 8, 'class_id_bits': 16,
                                  'null_register': 'x22', 'null_class_id': 1, 'allocation_result_register': 'x0',
                                  'pool_classes': [], 'allocation_returns': [], 'thread_heap_classes': [], 'entries': []},
            'receiver_certificates': [{'payload': 0x1000, 'blocks': [{'start': 0x1000, 'end': 0x100c,
                'entry': True, 'reachable': True,
                'facts': [[15, 8, '0x0', '0x0', '0x0'], [29, 8, '0x0', '0x1', '0x0']], 'compare': []}]}]}

    def check(self, graph):
        return check_receivers(graph, lambda address, length: self.raw,
                               lambda raw, address: list(self.decoder.disasm(raw, address)),
                               {'pool_heap_classes': [], 'class_allocations': [], 'thread_heap_classes': []})

    def test_original_stack_store(self):
        result = self.check(self.graph)
        self.assertEqual(result['stack_input_calls_checked'], 1)
        self.assertEqual(result['stack_input_slots_checked'], 1)

    def test_forged_stack_value_offset_kind_proof_and_duplicates(self):
        for key, value in [('value', '0x2'), ('sp_offset', 8), ('kind', 'heap_class'), ('proof', [0x1000])]:
            graph = copy.deepcopy(self.graph)
            graph['edges'][0]['stack_inputs'][0][key] = value
            with self.subTest(key=key), self.assertRaises((AssertionError, KeyError)):
                self.check(graph)
        graph = copy.deepcopy(self.graph)
        graph['edges'][0]['stack_inputs'] *= 2
        with self.assertRaises(AssertionError):
            self.check(graph)

    def test_modified_original_store_and_missing_certificate(self):
        # STR now targets an unrelated, unknown x16 base.
        self.raw = self.raw[:4] + (0xf9000200).to_bytes(4, 'little') + self.raw[8:]
        with self.assertRaises((AssertionError, KeyError)):
            self.check(self.graph)
        graph = copy.deepcopy(self.graph)
        graph['receiver_certificates'] = []
        with self.assertRaises(AssertionError):
            self.check(graph)

    def test_thread_class_requires_independent_audit(self):
        graph = copy.deepcopy(self.graph)
        graph['receiver_metadata']['thread_heap_classes'] = [[0xa8, 2]]
        with self.assertRaises(AssertionError):
            self.check(graph)

    def make_load(self):
        # STP x29,x30,[x15,#-16]!; MOV x29,x15; LDR x2,[x29,#16].
        self.raw = b''.join(w.to_bytes(4, 'little') for w in (0xa9bf79fd, 0xaa0f03fd, 0xf9400ba2))
        graph = copy.deepcopy(self.graph)
        graph['edges'] = []
        graph['entry_stack_loads'] = [{'site': 0x1008, 'payload': 0x1000, 'entry_sp_offset': 0,
                                      'register': 'x2', 'width': 8, 'proof': [0x1000, 0x1004, 0x1008]}]
        return graph

    def test_original_entry_stack_load(self):
        self.assertEqual(self.check(self.make_load())['entry_stack_loads_checked'], 1)

    def test_forged_load_offsets_register_width_and_frame_anchor(self):
        for key, value in [('entry_sp_offset', 16), ('register', 'x3'), ('width', 4), ('payload', 0x1004)]:
            graph = self.make_load()
            graph['entry_stack_loads'][0][key] = value
            with self.subTest(key=key), self.assertRaises(AssertionError):
                self.check(graph)
        graph = self.make_load()
        graph['receiver_certificates'][0]['blocks'][0]['facts'][0][3] = '0x1'
        with self.assertRaises(AssertionError):
            self.check(graph)


if __name__ == '__main__':
    unittest.main()
