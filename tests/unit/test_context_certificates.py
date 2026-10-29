"""Caller bindings must come from separately checked physical stores."""
import copy
from pathlib import Path
import sys
import unittest

import capstone

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
from check_receiver_analysis import check_receivers


class ContextCertificates(unittest.TestCase):
    def setUp(self):
        self.decoder = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
        self.decoder.detail = True
        def words(*values):
            return b''.join(w.to_bytes(4, 'little') for w in values)
        self.raw = {0x1000: words(0xd2800020, 0xf90001e0, 0x940003fe),
                    0x2000: words(0xf94001e0, 0xf8607abe, 0xd63f03c0)}
        self.graph = {
            'format': 6,
            'profile': {'pool_register': 'x27', 'thread_register': 'x26', 'dispatch_register': 'x21',
                        'pool_data_offset': 16, 'pool_slot_size': 8},
            'nodes': [{'start': 0x1000, 'end': 0x100c, 'names': []}, {'start': 0x2000, 'end': 0x200c, 'names': []}],
            'edges': [{'site': 0x1008, 'source': 0x1000, 'kind': 'call', 'target': 0x2000, 'stack_inputs': [
                {'sp_offset': 0, 'kind': 'word', 'value': '0x1', 'proof': [0x1000, 0x1004]}]},
                {'site': 0x2008, 'source': 0x2000, 'kind': 'indirect_call', 'target': None}],
            'dispatch_table': {'origin': 0, 'entries': [0x3000, 0x3004]},
            'receiver_metadata': {'header_displacement': -1, 'class_id_shift': 8, 'class_id_bits': 16,
                                  'null_register': 'x22', 'null_class_id': 1, 'allocation_result_register': 'x0',
                                  'pool_classes': [], 'allocation_returns': [], 'thread_heap_classes': [],
                                  'frame_preserving_calls': [], 'entries': [0x2000]},
            'receiver_certificates': [{'payload': 0x1000, 'blocks': [{'start': 0x1000, 'end': 0x100c,
                'entry': True, 'reachable': True, 'facts': [[15, 8, '0x0', '0x0', '0x0']], 'compare': [], 'live_inputs': []}]}],
            'call_contexts': [{'payload': 0x2000, 'callers': [0x1008],
                'inputs': [{'sp_offset': 0, 'kind': 'word', 'value': '0x1'}],
                'resolutions': [{'site': 0x2008, 'load': 0x2004, 'index': 1, 'table_index': 1,
                                 'snapshot_target': 0x3004, 'proof': [0x2000, 0x2004]}],
                'certificate': {'payload': 0x2000, 'blocks': [{'start': 0x2000, 'end': 0x200c, 'entry': True,
                    'reachable': True, 'facts': [[15, 8, '0x0', '0x0', '0x0'], [21, 6, '0x0', '0x0', '0x0']],
                    'compare': [], 'live_inputs': [0]}]}}]}

    def check(self, graph):
        return check_receivers(graph, lambda address, length: self.raw[address][:length],
                               lambda raw, address: list(self.decoder.disasm(raw, address)),
                               {'pool_heap_classes': [], 'class_allocations': [], 'thread_heap_classes': [],
                                'frame_preserving_calls': []})

    def test_original_context_and_caller(self):
        result = self.check(self.graph)
        self.assertEqual(result['call_contexts_checked'], 1)
        self.assertEqual(result['context_dispatches_checked'], 1)
        self.assertEqual(result['context_callers_checked'], 1)
        self.assertEqual(result['receiver_claims_checked'], 0)

    def test_forged_binding_value_kind_offset_and_caller(self):
        for key, value in [('value', '0x2'), ('kind', 'heap_class'), ('sp_offset', 8)]:
            graph = copy.deepcopy(self.graph)
            graph['call_contexts'][0]['inputs'][0][key] = value
            with self.subTest(key=key), self.assertRaises(AssertionError):
                self.check(graph)
        for callers in ([], [0x1008, 0x1008], [0x2008]):
            graph = copy.deepcopy(self.graph)
            graph['call_contexts'][0]['callers'] = callers
            with self.subTest(callers=callers), self.assertRaises(AssertionError):
                self.check(graph)

    def test_unverified_caller_store_cannot_seed_callee(self):
        graph = copy.deepcopy(self.graph)
        graph['receiver_certificates'] = []
        with self.assertRaises(AssertionError):
            self.check(graph)

    def test_forged_target_and_reintroduced_input(self):
        graph = copy.deepcopy(self.graph)
        graph['call_contexts'][0]['resolutions'][0]['snapshot_target'] = 0x3000
        with self.assertRaises(AssertionError):
            self.check(graph)
        graph = copy.deepcopy(self.graph)
        graph['call_contexts'][0]['certificate']['blocks'][0]['live_inputs'] = []
        with self.assertRaises(AssertionError):
            self.check(graph)

    def test_duplicate_context_and_unverified_call_contract(self):
        graph = copy.deepcopy(self.graph)
        graph['call_contexts'] *= 2
        with self.assertRaises(AssertionError):
            self.check(graph)
        graph = copy.deepcopy(self.graph)
        graph['receiver_metadata']['frame_preserving_calls'] = [[0x1008, 'stack_overflow_without_fpu']]
        with self.assertRaises(AssertionError):
            self.check(graph)

    def test_atomic_and_opaque_writes_cannot_preserve_a_stale_binding(self):
        # LLVM-checked original encodings: STLR xzr,[x15], STXR w7,xzr,[x15],
        # and DC ZVA,x15. Atomic memory access flags alone miss the first store.
        original = self.raw[0x2000]
        for word in (0xc89ffdff, 0xc8077dff, 0xd50b742f):
            graph = copy.deepcopy(self.graph)
            self.raw[0x2000] = word.to_bytes(4, 'little') + original
            graph['nodes'][1]['end'] = 0x2010
            graph['edges'][1]['site'] = 0x200c
            context = graph['call_contexts'][0]
            context['certificate']['blocks'][0]['end'] = 0x2010
            context['resolutions'][0].update(site=0x200c, load=0x2008, proof=[0x2004, 0x2008])
            with self.subTest(word=hex(word)), self.assertRaises(AssertionError):
                self.check(graph)


if __name__ == '__main__':
    unittest.main()
