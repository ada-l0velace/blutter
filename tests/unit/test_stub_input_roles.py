import copy
from pathlib import Path
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
from stub_input_roles import contracts, check_contracts, input_records
from check_call_result_notes import expected_facts, check_stream
from query_register_inputs import query, render


class StubInputRolesTests(unittest.TestCase):
    def setUp(self):
        self.roles = [{'register': 'x2', 'role': 'array_length'}, {'register': 'x1', 'role': 'array_type_arguments'}]
        self.contract = dict(entry=0x2000, end=0x2004, kind='allocate_array', basis='matched_sdk_stub_identity', inputs=self.roles)
        self.edge = dict(source=0x1000, site=0x1008, kind='call', target=0x2000, register_inputs=[dict(register='x1', class_id=7)],
                         register_constants=[dict(register='x2', bits='0x6')], static_dispatch=None,
                         stack_inputs=[], array_arguments=[])
        self.graph = dict(format=33, nodes=[dict(start=0x2000, end=0x2004)], stub_input_contracts=[self.contract],
                          edges=[self.edge], receiver_metadata={}, register_contexts=[])
        self.audit = dict(stub_input_abis=[dict(kind='allocate_array', inputs=self.roles)],
                          stub_input_references=[dict(kind='allocate_array', bytes='c0035fd6')],
                          stub_input_identities=[dict(entry=0x2000, payload=0x2000, end=0x2004, kind='allocate_array')])

    def test_full_identity(self):
        self.assertEqual(check_contracts(self.graph, self.audit, lambda a, n: bytes.fromhex('c0035fd6')), 1)
        for field in ('end', 'payload'):
            bad = copy.deepcopy(self.audit); bad['stub_input_identities'][0][field] += 4
            with self.assertRaises(AssertionError): check_contracts(self.graph, bad, lambda a, n: b'')
        with self.assertRaises(AssertionError): check_contracts(self.graph, self.audit, lambda a, n: b'bad!')
        with self.assertRaises(AssertionError): check_contracts(self.graph, None, lambda a, n: b'')

    def test_contract_forgery(self):
        for defect in ('role', 'reg', 'basis', 'end', 'duplicate', 'missing'):
            with self.subTest(defect=defect):
                bad = copy.deepcopy(self.graph)
                row = bad['stub_input_contracts'][0]
                if defect == 'role': row['inputs'][0]['role'] = 'closure_context'
                if defect == 'reg': row['inputs'][0]['register'] = 'x15'
                if defect == 'basis': row['basis'] = 'name_match'
                if defect == 'end': row['end'] = row['entry']
                if defect == 'duplicate': bad['stub_input_contracts'].append(copy.deepcopy(row))
                if defect == 'missing': del bad['stub_input_contracts']
                with self.assertRaises((AssertionError, KeyError)): contracts(bad)

    def test_roles_and_raw_values(self):
        rows = list(input_records(self.graph))
        self.assertEqual([(v['role'], v['kind'], v['value']) for v in rows],
                         [('array_type_arguments', 'class', 7), ('array_length', 'word', 6)])
        self.edge['register_constants'] = []
        self.assertEqual(list(input_records(self.graph))[1]['kind'], 'unknown')
        self.edge['target'] += 4
        self.assertIsNone(list(input_records(self.graph))[0]['role'])

    def test_indirect_scope(self):
        self.edge.update(kind='indirect_call', target=None)
        self.assertFalse(any(v['role'] for v in input_records(self.graph)))
        resolution = dict(site=0x1008, load=0x1004, snapshot_target=0x2000, proof=[0x1004])
        binding = dict(site=0x1000, callee=0x3000, class_id=9, basis='machine_return_summary')
        context = dict(payload=0x1000, resolutions=[resolution], return_bindings=[binding],
                       register_observations=[dict(site=0x1008, values=[dict(register='x1', class_id=7)])])
        self.graph['call_result_contexts'] = [context]
        rows = list(input_records(self.graph))
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[1]['bindings'], [binding])
        self.assertEqual(rows[1]['role'], 'array_type_arguments')
        self.edge['static_dispatch'] = resolution
        self.assertEqual(len(list(input_records(self.graph))), 2)  # ordinary class plus ordinary unknown/word
        resolution['proof'] = [0x1001]
        with self.assertRaises(AssertionError): list(input_records(self.graph))

    def test_render_and_negative_labels(self):
        lines = ['// call-input @0x1008 [payload 0x1000]: array type arguments (X1) -> class 0x7 [stub 0x2000; partial; normal flow]\n',
                 '// call-input @0x1008 [payload 0x1000]: array length (X2) -> raw word 0x6 [stub 0x2000; partial; normal flow]\n',
                 '// 0x1008: bl #0x2000\n']
        facts = expected_facts(self.graph)
        self.assertEqual(set(check_stream(lines, facts)[0]), facts)
        for old, new in [('array length', 'closure context'), ('0x2000; partial', '0x2004; partial'),
                         ('raw word 0x6', 'raw word 0x3'), ('(X2)', '(X3)'), ('normal flow', 'under result bindings 0x1000@0x3000=0x9')]:
            forged = [v.replace(old, new) for v in lines]
            with self.assertRaises(AssertionError): check_stream(forged, facts)
        result = query(self.graph, 0x1008)
        self.assertEqual(len(result['stub_input_roles']), 2)
        self.assertIn('array length (x2) -> raw word 0x6', render(result))

    def test_legacy_graph(self):
        self.graph['format'] = 32; del self.graph['stub_input_contracts']
        self.assertTrue(all(v['role'] is None for v in input_records(self.graph)))
        self.assertEqual(check_contracts(self.graph, None, None), 0)


if __name__ == '__main__':
    unittest.main()
