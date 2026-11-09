import copy
import gzip
import json
from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
from call_input_shapes import shapes, check_shapes, input_records
from query_call_inputs import query, render
from check_call_result_notes import expected_facts, check_stream
from graph_io import load_graph


class CallInputShapeTests(unittest.TestCase):
    def setUp(self):
        self.model = dict(entry=0x2000, fixed=3, implicit=0, type_parameters=2, name='authored"\n',
                          basis='compatible_retained_signature', declared_types=['Object', 'Object', 'Object'])
        self.descriptor = dict(pool_index=6, type_arguments=2, count=3, size=3, positional=3)
        self.shape = dict(site=0x100c, payload=0x1000, target=0x2000, load=0x1008, pool_index=6, count=3,
                          word_bytes=8, basis='immediate_descriptor_fixed_stack', proof=[0x1008, 0x100c])
        self.edge = dict(site=0x100c, source=0x1000, kind='call', target=0x2000,
                         stack_inputs=[dict(sp_offset=16, kind='heap_class', value='0x7', proof=[0x1000]),
                                       dict(sp_offset=0, kind='word', value='0x28', proof=[0x1004])],
                         register_inputs=[], array_arguments=[], register_constants=[])
        self.graph = dict(format=34, call_input_abi=dict(supported=True, reason='verified_compiler_policy', descriptor_register=4, word_bytes=8),
                          call_input_descriptors=[self.descriptor], call_input_models=[self.model], call_input_shapes=[self.shape], call_input_rejections=[],
                          nodes=[dict(start=0x1000, end=0x1014, decoded=True, names=[]), dict(start=0x2000, end=0x2008, decoded=True, names=[])],
                          edges=[self.edge], stub_input_contracts=[],
                          profile=dict(pool_data_offset=16, pool_slot_size=8), references=[dict(site=0x1008, payload=0x1000, kind='pool', access='load',
                          offset=64, width=8, pool_index=6, base_register='x27', proof=[])])
        self.audit = dict(call_input_abi=dict(supported=True, descriptor_register=4, word_bytes=8), call_input_descriptors=[copy.deepcopy(self.descriptor)],
                          function_metadata=[dict(entry=0x2000, kind=0, name=self.model['name'], call_input_model=dict(fixed=3, implicit=0, implicit_from_kind=0,
                          optional=0, type_parameters=2, parent_type_arguments=0, static=True, native=False, abstract=False, declared_types=self.model['declared_types']))])
        self.words = {0x1008: (0xf9400000 | (8 << 10) | (27 << 5) | 4), 0x100c: (0x94000000 | ((0x2000-0x100c)//4))}

    def read(self, address, size):
        self.assertEqual(size % 4, 0)
        return b''.join(self.words.get(a, 0xd503201f).to_bytes(4, 'little') for a in range(address, address+size, 4))

    def test_numerical_audit_and_coverage(self):
        self.assertEqual(check_shapes(self.graph, self.audit, self.read), 1)
        bad = copy.deepcopy(self.graph)
        for k in ('call_input_shapes', 'call_input_models', 'call_input_descriptors'): bad[k] = []
        with self.assertRaises(AssertionError): check_shapes(bad, self.audit, self.read)
        with self.assertRaises(AssertionError): check_shapes(self.graph, None, self.read)

    def test_independent_forgeries(self):
        for defect in ('descriptor', 'register', 'word_width', 'target', 'entry', 'proof', 'count', 'model', 'alias', 'pool', 'type', 'disabled', 'bool'):
            with self.subTest(defect=defect):
                g, a, w = copy.deepcopy(self.graph), copy.deepcopy(self.audit), dict(self.words)
                if defect == 'descriptor': a['call_input_descriptors'][0]['type_arguments'] = 0
                if defect == 'register': w[0x1008] -= 1
                if defect == 'word_width': w[0x1008] &= ~(1 << 30)
                if defect == 'target': w[0x100c] += 1
                if defect == 'entry': g['nodes'][0]['names'] = [dict(address=0x100c)]
                if defect == 'proof': g['call_input_shapes'][0]['proof'] = [0x100c]
                if defect == 'count': g['call_input_shapes'][0]['count'] = 2
                if defect == 'model': a['function_metadata'][0]['call_input_model']['native'] = True
                if defect == 'alias': a['function_metadata'] *= 2
                if defect == 'pool': g['references'][0]['pool_index'] = 7
                if defect == 'type': g['call_input_models'][0]['declared_types'][0] = 'Invented'
                if defect == 'disabled': g['call_input_abi']['supported'] = False
                if defect == 'bool': g['call_input_shapes'][0]['pool_index'] = True
                with self.assertRaises((AssertionError, KeyError)): check_shapes(g, a, lambda address, size: b''.join(w.get(a, 0xd503201f).to_bytes(4, 'little') for a in range(address, address+size, 4)))

    def test_original_conditional_branch_bypass(self):
        for opcode, shift in ((0x34000000, 5), (0x54000000, 5), (0x36000000, 5)):
            self.words[0x1000] = opcode | (3 << shift)
            with self.assertRaises(AssertionError): check_shapes(self.graph, self.audit, self.read)
        self.words[0x1000] = 0xd503201f
        self.assertEqual(check_shapes(self.graph, self.audit, self.read), 1)

    def test_multi_input_query_and_unknowns(self):
        result = query(self.graph, 0x100c)
        self.assertEqual([(v['index'], v['sp_offset'], v['kind']) for v in result['inputs']], [(0, 16, 'heap_class'), (1, 8, 'unknown'), (2, 0, 'word')])
        text = render(result)
        self.assertIn('input[1] (Dart SP+8) -> value unknown', text)
        self.assertIn('raw word 0x28', text)
        self.assertIn('authored\\"\\n', text)
        self.assertEqual(len(list(input_records(self.graph))), 2)

    def test_conditions_and_comment_forgeries(self):
        binding = dict(site=0x1000, callee=0x3000, class_id=9, basis='machine_return_summary')
        values = copy.deepcopy(self.edge['stack_inputs']) + [dict(sp_offset=8, kind='heap_class', value='0xb', proof=[0x1000])]
        self.graph['call_result_contexts'] = [dict(payload=0x1000, return_bindings=[binding], stack_observations=[dict(site=0x100c, values=values)],
                                                 array_observations=[], resolutions=[], certificate={}, register_observations=[])]
        rows = list(input_records(self.graph)); self.assertEqual(len(rows), 3)
        self.assertEqual(rows[-1]['bindings'], [binding])
        lines = ['// call-input @0x100c [payload 0x1000]: supplied input[0] (Dart SP+16) -> class 0x7 [descriptor load 0x1008; fixed stack; partial; normal flow]\n',
                 '// call-input @0x100c [payload 0x1000]: supplied input[2] (Dart SP+0) -> raw word 0x28 [descriptor load 0x1008; fixed stack; partial; normal flow]\n',
                 '// call-input @0x100c [payload 0x1000]: supplied input[1] (Dart SP+8) -> class 0xb [descriptor load 0x1008; fixed stack; partial; under result bindings 0x1000@0x3000=0x9]\n',
                 '// 0x100c: bl #0x2000\n']
        facts = {v for v in expected_facts(self.graph) if v[2] == 'supplied_input'}
        self.assertEqual(set(check_stream(lines, facts)[0]), facts)
        for old, new in [('input[0]', 'input[1]'), ('SP+16', 'SP+8'), ('load 0x1008', 'load 0x1004'), ('raw word 0x28', 'raw word 0x14'), ('under result bindings 0x1000@0x3000=0x9', 'normal flow')]:
            with self.assertRaises(AssertionError): check_stream([line.replace(old, new) for line in lines], facts)

    def test_matched_async_completion_query(self):
        for key in ('call_input_shapes','call_input_models','call_input_descriptors'):
            self.graph[key]=[]
        self.edge['kind']='jump'
        with self.assertRaises(ValueError):query(self.graph,0x100c)
        self.graph['async_boundaries']=[dict(site=0x100c,operation='complete_value')]
        self.graph['call_input_origins']=[dict(site=0x100c,role='completion_operand',index=None,register=0,
            chain=[dict(relation='input',source=None,stop='control_transfer',pool_index=None)])]
        result=query(self.graph,0x100c)
        self.assertEqual(result['selection_reason'],'not_an_ordinary_call_packet')
        self.assertIn('Async completion',render(result))
        self.assertIn('Origin of completion_operand (X0)',render(result))

    def test_modes_and_legacy(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); raw = json.dumps(self.graph).encode()
            (root / 'full.json').write_bytes(raw)
            (root / 'compact.json.gz').write_bytes(gzip.compress(raw))
            self.assertEqual(query(load_graph(root / 'full.json'), 0x100c), query(load_graph(root / 'compact.json.gz'), 0x100c))
        self.graph['format'] = 33
        for k in ('call_input_abi', 'call_input_descriptors', 'call_input_models', 'call_input_shapes', 'call_input_rejections'): del self.graph[k]
        self.assertEqual(query(self.graph, 0x100c)['selection_reason'], 'legacy_graph')
        self.assertEqual(check_shapes(self.graph, None, None), 0)


if __name__ == '__main__': unittest.main()
