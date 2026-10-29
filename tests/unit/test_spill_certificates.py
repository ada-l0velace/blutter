"""Authored original-word spill proofs and independently audited stub facts."""
import copy
from pathlib import Path
import sys
import unittest

import capstone

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
from check_receiver_analysis import check_receivers


class SpillCertificates(unittest.TestCase):
    def setUp(self):
        self.decoder = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
        self.decoder.detail = True
        # Frame; pool load; spill; BL allocator; reload; header; CID; GDT; BLR.
        self.raw = b''.join(w.to_bytes(4, 'little') for w in (
            0xa9bf79fd, 0xaa0f03fd, 0xd10081ef, 0xf9401760, 0xf81f83a0,
            0x94000ffb, 0xf85f83a2, 0xf85ff040, 0xd3485c00, 0xf8607abe, 0xd63f03c0))
        self.audit = {'pool_heap_classes': [[3, 1]], 'class_allocations': [],
                      'predefined_allocations': [[0x5000, 2]], 'thread_heap_classes': [],
                      'frame_preserving_calls': [], 'preserved_call_registers': []}
        self.graph = {
            'format': 7,
            'profile': {'pool_register': 'x27', 'thread_register': 'x26', 'dispatch_register': 'x21',
                        'pool_data_offset': 16, 'pool_slot_size': 8},
            'nodes': [{'start': 0x1000, 'end': 0x102c, 'names': []}],
            'edges': [{'site': 0x1014, 'source': 0x1000, 'kind': 'call', 'target': 0x5000},
                {'site': 0x1028, 'source': 0x1000, 'kind': 'indirect_call', 'target': None,
                 'static_dispatch': {'load': 0x1024, 'index': 1, 'table_index': 1, 'snapshot_target': 0x2004,
                                     'proof': list(range(0x1000, 0x1028, 4))}}],
            'dispatch_table': {'origin': 0, 'entries': [0x2000, 0x2004]},
            'receiver_metadata': {'header_displacement': -1, 'class_id_shift': 8, 'class_id_bits': 16,
                                  'null_register': 'x22', 'null_class_id': 1, 'allocation_result_register': 'x0',
                                  'pool_classes': [[3, 1]], 'allocation_returns': [[0x5000, 2]],
                                  'thread_heap_classes': [], 'frame_preserving_calls': [],
                                  'preserved_call_registers': [], 'entries': []},
            'receiver_certificates': [{'payload': 0x1000, 'blocks': [
                {'start': 0x1000, 'end': 0x1018, 'entry': True, 'reachable': True,
                 'facts': [[15, 8, '0x0', '0x0', '0x0'], [21, 6, '0x0', '0x0', '0x0'],
                           [27, 5, '0x0', '0x0', '0x0'], [29, 8, '0x0', '0x1', '0x0']],
                 'compare': [], 'live_inputs': [], 'spills': []},
                {'start': 0x1018, 'end': 0x102c, 'entry': False, 'reachable': True,
                 'facts': [[15, 8, '0xffffffffffffffd0', '0x0', '0x0'], [21, 6, '0x0', '0x0', '0x0'],
                           [29, 8, '0xfffffffffffffff0', '0x0', '0x0']],
                 'compare': [], 'live_inputs': [], 'spills': [[-24, 1]]}]}]}

    def check(self, graph=None):
        return check_receivers(graph or self.graph, lambda address, length: self.raw,
                               lambda raw, address: list(self.decoder.disasm(raw, address)), self.audit)

    def test_original_spill_and_known_allocator_call(self):
        self.assertEqual(self.check()['receiver_claims_checked'], 1)

    def test_changed_or_missing_store_does_not_establish_spill(self):
        original = self.raw
        for word in (0xd503201f, 0xb81f83a0):  # NOP or STUR w0,[FP,#-8].
            self.raw = original[:16] + word.to_bytes(4, 'little') + original[20:]
            with self.subTest(word=hex(word)), self.assertRaises(AssertionError):
                self.check()

    def test_unknown_call_does_not_preserve_spill(self):
        self.raw = self.raw[:20] + (0x94000ffc).to_bytes(4, 'little') + self.raw[24:]
        self.graph['edges'][0]['target'] = 0x5004
        with self.assertRaises(AssertionError):
            self.check()

    def test_narrow_reload_does_not_recover_heap_class(self):
        self.raw = self.raw[:24] + (0xb85f83a2).to_bytes(4, 'little') + self.raw[28:]
        with self.assertRaises(AssertionError):
            self.check()

    def test_forged_spill_facts_and_entry_seed_fail(self):
        for cells in ([[-24, 2]], [[0, 1]], [[-23, 1]], [[-24, 1], [-24, 1]]):
            graph = copy.deepcopy(self.graph)
            graph['receiver_certificates'][0]['blocks'][1]['spills'] = cells
            with self.subTest(cells=cells), self.assertRaises(AssertionError):
                self.check(graph)
        graph = copy.deepcopy(self.graph)
        graph['receiver_certificates'][0]['blocks'][0]['spills'] = [[-24, 1]]
        with self.assertRaises(AssertionError):
            self.check(graph)

    def test_predefined_return_class_requires_matching_audit(self):
        for rows in ([], [[0x5000, 3]]):
            self.audit['predefined_allocations'] = rows
            with self.subTest(rows=rows), self.assertRaises(AssertionError):
                self.check()

    def test_register_preservation_requires_matching_safe_contract(self):
        self.graph['receiver_metadata']['preserved_call_registers'] = [[0x5000, 4]]
        with self.assertRaises(AssertionError):
            self.check()
        self.graph['receiver_metadata']['preserved_call_registers'] = [[0x5000, 1 << 15]]
        self.audit['preserved_call_registers'] = [[0x5000, 1 << 15]]
        with self.assertRaises(AssertionError):
            self.check()


if __name__ == '__main__':
    unittest.main()
