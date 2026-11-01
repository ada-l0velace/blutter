"""Authored register/return certificates, bindings and adversarial controls."""
import copy
from pathlib import Path
import sys
import unittest

import capstone

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
from check_receiver_analysis import check_receivers
from check_register_inputs import register_claims, check_register_bindings, check_return_summary
from query_register_inputs import query, render


class RegisterInputs(unittest.TestCase):
    def setUp(self):
        self.decoder = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
        self.decoder.detail = True
        self.words = {0x1000: [0xf9401761, 0x940003ff, 0xd65f03c0], 0x2000: [0xaa0103e0, 0xd65f03c0]}
        roots = [[15, 8, '0x0', '0x0', '0x0'], [21, 6, '0x0', '0x0', '0x0'],
                 [22, 3, '0x1', '0x0', '0x0'], [26, 9, '0x0', '0x0', '0x0'],
                 [27, 5, '0x0', '0x0', '0x0'], [29, 8, '0x0', '0x1', '0x0']]
        def block(start, end, entry, facts):
            return {'start': start, 'end': end, 'entry': entry, 'reachable': True, 'facts': copy.deepcopy(facts),
                    'compare': [], 'spills': [], 'live_inputs': [], 'fresh_array': None, 'array_continuation': None}
        returned = {'site': 0x2004, 'class_id': 7, 'register': 'x0', 'proof': [0x2000, 0x2004]}
        self.graph = {'format': 24,
            'profile': {'pool_register': 'x27', 'thread_register': 'x26', 'dispatch_register': 'x21', 'pool_data_offset': 16, 'pool_slot_size': 8},
            'nodes': [{'start': 0x1000, 'end': 0x100c, 'names': [], 'label': 'caller'},
                      {'start': 0x2000, 'end': 0x2008, 'names': [], 'label': 'helper'}],
            'edges': [{'site': 0x1004, 'source': 0x1000, 'kind': 'call', 'target': 0x2000,
                       'register_inputs': [{'register': 'x1', 'class_id': 7, 'proof': [0x1000]}]}],
            'dispatch_table': {'origin': 0, 'entries': []},
            'receiver_metadata': {'header_displacement': -1, 'class_id_shift': 8, 'class_id_bits': 16,
                'null_register': 'x22', 'null_class_id': 1, 'allocation_result_register': 'x0', 'word_return_register': 'x0',
                'pool_classes': [[3, 7]], 'allocation_returns': [], 'entries': [0x2000], 'stack_limit_offset': None},
            'receiver_certificates': [{'payload': 0x1000, 'blocks': [block(0x1000, 0x1008, True, roots), block(0x1008, 0x100c, False, roots)], 'return_classes': [], 'normal_return_class': None}],
            'register_contexts': [{'payload': 0x2000, 'callers': [0x1004], 'inputs': [],
                'register_inputs': [{'register': 'x1', 'class_id': 7}], 'resolutions': [], 'forwarded_returns': [],
                'array_length_returns': [], 'stack_observations': [], 'normal_return_class': 7,
                'certificate': {'payload': 0x2000, 'blocks': [block(0x2000, 0x2008, True, roots+[[1, 3, '0x7', '0x0', '0x0']])],
                                'return_classes': [returned], 'normal_return_class': 7}}]}
        self.audit = {'pool_heap_classes': [[3, 7]], 'class_allocations': [], 'thread_heap_classes': [],
                      'frame_preserving_calls': [], 'preserved_call_registers': [], 'stack_limit_offset': None,
                      'word_return_register': 'x0'}

    def read(self, address, length):
        for start, words in self.words.items():
            raw = b''.join(w.to_bytes(4, 'little') for w in words)
            if start <= address and address+length <= start+len(raw):
                return raw[address-start:address-start+length]
        raise AssertionError('Address outside authored fixture')

    def check(self):
        return check_receivers(self.graph, self.read, lambda raw, address: list(self.decoder.disasm(raw, address)), self.audit)

    def test_original_word_binding_and_conditional_result(self):
        result = self.check()
        self.assertEqual(result['register_observation_classes_checked'], 1)
        self.assertEqual(result['register_contexts_checked'], 1)
        self.assertEqual(result['physical_return_classes_checked'], 1)

    def test_new_dispatches_do_not_change_legacy_context_counters(self):
        self.words[0x2000] = [0xb85ff020, 0xd3485c00, 0xf8607abe, 0xd63f03c0]
        self.graph['nodes'][1]['end'] = 0x2010
        self.graph['dispatch_table']['entries'] = [None]*7 + [0x3000]
        self.graph['receiver_metadata']['entries'].append(0x3000)
        self.graph['edges'].append({'site': 0x200c, 'source': 0x2000, 'kind': 'indirect_call', 'target': None})
        context = self.graph['register_contexts'][0]
        context['normal_return_class'] = None
        context['resolutions'] = [{'site': 0x200c, 'load': 0x2008, 'index': 7, 'table_index': 7,
                                  'snapshot_target': 0x3000, 'proof': [0x2000, 0x2004, 0x2008]}]
        context['certificate']['blocks'][0]['end'] = 0x2010
        context['certificate'].update(return_classes=[], normal_return_class=None)
        result = self.check()
        self.assertEqual(result['register_context_dispatches_checked'], 1)
        self.assertEqual(result['context_dispatches_checked'], 0)
        context['resolutions'] *= 2
        with self.assertRaises(AssertionError): self.check()

    def test_forged_observation_or_original_load_fails(self):
        self.graph['edges'][0]['register_inputs'][0]['class_id'] = 8
        with self.assertRaises(AssertionError): self.check()
        self.setUp(); self.words[0x1000][0] = 0xd503201f
        with self.assertRaises(AssertionError): self.check()

    def test_reserved_duplicate_and_malformed_registers_fail(self):
        for name, cid in [('x15', 7), ('w1', 7), ('x1', True), ('x1', 0), ('x1', 65536)]:
            with self.subTest(name=name, cid=cid):
                self.setUp(); self.graph['edges'][0]['register_inputs'][0].update(register=name, class_id=cid)
                with self.assertRaises(AssertionError): self.check()
        self.setUp(); self.graph['edges'][0]['register_inputs'] *= 2
        with self.assertRaises(AssertionError): self.check()

    def test_wrong_caller_target_binding_or_return_fails(self):
        for defect in ('caller', 'binding', 'return', 'summary', 'scope', 'duplicate-context'):
            with self.subTest(defect=defect):
                self.setUp(); context = self.graph['register_contexts'][0]
                if defect == 'caller': self.graph['edges'][0]['target'] = 0x3000
                elif defect == 'binding': context['register_inputs'][0]['class_id'] = 8
                elif defect == 'return': context['certificate']['return_classes'][0]['class_id'] = 8
                elif defect == 'summary': context['normal_return_class'] = 8
                elif defect == 'scope': context['path_condition'] = {}
                else: self.graph['register_contexts'] *= 2
                with self.assertRaises(AssertionError): self.check()

    def test_context_return_cannot_be_promoted_to_global_summary(self):
        self.graph['receiver_metadata']['machine_return_classes'] = [[0x2000, 7]]
        with self.assertRaises(AssertionError): self.check()

    def test_unknown_call_cannot_recreate_bound_register(self):
        self.words[0x2000] = [0x94000400, 0xaa0103e0, 0xd65f03c0]
        self.graph['nodes'][1]['end'] = 0x200c
        self.graph['receiver_metadata']['entries'].append(0x3000)
        context = self.graph['register_contexts'][0]
        first = context['certificate']['blocks'][0]
        second = copy.deepcopy(first); first['end'] = 0x2004
        second.update(start=0x2004, end=0x200c, entry=False)
        context['certificate']['blocks'].append(second)
        context['certificate']['return_classes'][0].update(site=0x2008, proof=[0x2004, 0x2008])
        with self.assertRaises(AssertionError): self.check()

    def test_closed_return_summary_rejects_tail_and_fallthrough(self):
        claim = {'site': 0x1004, 'class_id': 7, 'register': 'x0', 'proof': [0x1000, 0x1004]}
        certificate = {'return_classes': [claim], 'normal_return_class': 7}
        for words in ([0xf9401760, 0xd65f03c0, 0x14000400], [0xf9401760, 0xd65f03c0, 0xd503201f], [0xf9401760, 0xd65f03c0, 0xd65f0040]):
            raw = b''.join(w.to_bytes(4, 'little') for w in words)
            instructions = list(self.decoder.disasm(raw, 0x1000))
            with self.subTest(words=words), self.assertRaises(AssertionError):
                check_return_summary(certificate, instructions, {0x1004}, {0x1004}, set())

    def test_query_keeps_bindings_and_result_scope_visible(self):
        result = query(self.graph, 0x1004)
        self.assertEqual(result['contexts'][0]['normal_return_class'], 7)
        self.assertIsNone(result['callee_normal_return_class'])
        text = render(result)
        self.assertIn('x1: class 0x7', text)
        self.assertIn('Caller-qualified helper context', text)
        self.assertIn('not complete source arguments', text)
        with self.assertRaises(ValueError): query(self.graph, 0x1000)
        self.graph['format'] = 23
        with self.assertRaises(ValueError): query(self.graph, 0x1004)


if __name__ == '__main__':
    unittest.main()
