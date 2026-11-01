"""Authored exact-call return bindings and independent consumer checks."""
import copy
import unittest

import test_register_inputs as register_fixtures
from query_register_inputs import query, render
from check_call_results import check_result_bindings


class CallResults(unittest.TestCase):
    def setUp(self):
        fixture = register_fixtures.RegisterInputs(); fixture.setUp()
        self.fixture = fixture
        self.graph = fixture.graph
        certificate = copy.deepcopy(self.graph['receiver_certificates'][0])
        certificate['blocks'][1]['facts'].append([0, 3, '0x7', '0x0', '0x0'])
        certificate.update(return_classes=[{'site': 0x1008, 'class_id': 7, 'register': 'x0', 'proof': [0x1004, 0x1008]}], normal_return_class=7)
        self.graph['call_result_contexts'] = [{'payload': 0x1000, 'inputs': [],
            'return_bindings': [{'site': 0x1004, 'callee': 0x2000, 'class_id': 7, 'basis': 'register_context'}],
            'resolutions': [], 'forwarded_returns': [], 'array_length_returns': [], 'stack_observations': [],
            'array_observations': [], 'normal_return_class': 7, 'certificate': certificate}]

    def check(self):
        return self.fixture.check()

    def test_conditional_helper_result_reaches_original_caller(self):
        result = self.check()
        self.assertEqual(result['call_result_contexts_checked'], 1)
        self.assertEqual(result['physical_return_classes_checked'], 2)

    def test_wrong_site_target_class_or_basis_fails(self):
        for key, value in [('site', 0x1000), ('callee', 0x2004), ('class_id', 8), ('class_id', True),
                           ('basis', 'machine_return_summary'), ('basis', 'function_name')]:
            with self.subTest(key=key, value=value):
                self.setUp(); self.graph['call_result_contexts'][0]['return_bindings'][0][key] = value
                with self.assertRaises((AssertionError, KeyError)): self.check()

    def test_missing_or_changed_producer_cannot_support_consumer(self):
        self.graph['register_contexts'] = []
        with self.assertRaises(AssertionError): self.check()
        self.setUp(); self.graph['register_contexts'][0]['normal_return_class'] = None
        with self.assertRaises(AssertionError): self.check()

    def test_consumer_cannot_supply_its_own_global_producer(self):
        self.graph['receiver_metadata']['machine_return_classes'] = [[0x1000, 7]]
        with self.assertRaises(AssertionError): self.check()

    def test_result_context_cannot_invent_entry_inputs(self):
        context = self.graph['call_result_contexts'][0]
        context['inputs'] = [{'sp_offset': 0, 'kind': 'heap_class', 'value': '0x7'}]
        with self.assertRaises(AssertionError): self.check()
        self.setUp(); self.graph['call_result_contexts'][0]['register_inputs'] = [{'register': 'x1', 'class_id': 7}]
        with self.assertRaises(AssertionError): self.check()

    def test_duplicate_context_or_forged_return_fails(self):
        self.graph['call_result_contexts'] *= 2
        with self.assertRaises(AssertionError): self.check()
        self.setUp(); self.graph['call_result_contexts'][0]['certificate']['return_classes'][0]['class_id'] = 8
        with self.assertRaises(AssertionError): self.check()
        self.setUp(); self.graph['call_result_contexts'][0]['resolutions'] = [{'site': 0x1008}]*2
        with self.assertRaises(AssertionError): check_result_bindings(self.graph, {})

    def test_query_keeps_call_site_and_producer_basis_visible(self):
        result = query(self.graph, 0x1004)
        self.assertEqual(result['call_result_contexts'][0]['return_bindings'][0]['site'], 0x1004)
        self.assertIn('Separate caller result propagation', render(result))
        self.assertIn('[register_context]', render(result))


if __name__ == '__main__':
    unittest.main()
