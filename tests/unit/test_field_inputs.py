import copy
import gzip
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
from async_future_bindings import CONDITIONS
from field_input_origins import SCOPE, check_field_inputs, check_stream, note
from query_field_inputs import query, render
from graph_io import load_graph


class FieldInputTests(unittest.TestCase):
    def setUp(self):
        self.field = dict(payload=0x1000, source_await=0x1004, seed=0x1008, register=0,
            class_id=7, basis='await_delivery', status='registers_lost', steps=2,
            scope='conditional_layout_only', accesses=[dict(site=0x1008, base=0, register=1,
                bytes=4, offset=8, access='read', kind='instance_slot', index=None)])
        self.origin = dict(site=0x1014, payload=0x1000, role='array_type_arguments', index=None,
            register=1, sp_offset=None, condition='normal_fallthrough', chain=[dict(relation='input',
                stop='load_endpoint', steps=3, pool_index=None, source=dict(kind='load_compressed',
                site=0x1008, callee=None, bits=None, load=dict(base=0, displacement=7, bytes=4),
                proof=[0x1008, 0x100c, 0x1010, 0x1014]))])
        self.link = dict(context=0, access=0, input_origin=0, scope=SCOPE)
        self.graph = dict(format=41, async_field_input_links=[self.link],
            async_field_work=dict(supported=True),
            async_field_input_work=dict(limit=200000, link_limit=4096, origins_examined=1,
                candidates=1, remaining=199999, complete=True),
            call_input_origins=[self.origin], async_field_contexts=[self.field],
            async_field_layouts=[dict(class_id=7, kind='instance', tag=1, slot_bytes=4, fields=[])],
            call_input_abi=dict(supported=True, word_bytes=8), call_input_shapes=[],
            stub_input_contracts=[dict(entry=0x2000, inputs=[dict(register='x1', role='array_type_arguments')])],
            async_contracts=[], edges=[dict(site=0x1014, source=0x1000, kind='call', target=0x2000)],
            receiver_metadata=dict(null_class_id=1), saved_reference_contexts=[],
            await_future_bindings=[dict(site=0x1004, payload=0x1000, resume_site=0x1008,
                status='conditional_delivery', value='heap_class', class_id=7, conditions=list(CONDITIONS))])

    def test_direct_role_and_unknown_value(self):
        self.assertEqual(check_field_inputs(self.graph), 1)
        text = render(query(self.graph, 0x1014))
        self.assertIn('array type arguments (X1)', text)
        self.assertIn('field value/type unknown', text)
        self.assertIn('copied loaded word only', text)

    def test_role_evidence_required(self):
        for change in ('contract', 'register', 'target', 'physical', 'abi'):
            g = copy.deepcopy(self.graph)
            if change == 'contract': g['stub_input_contracts'] = []
            if change == 'register': g['call_input_origins'][0]['register'] = 2
            if change == 'target': g['edges'][0]['target'] = 0x3000
            if change == 'physical': g['call_input_origins'][0]['role'] = 'physical_register'
            if change == 'abi': g['call_input_abi']['supported'] = False
            with self.subTest(change=change), self.assertRaises(AssertionError):
                check_field_inputs(g)

    def test_load_and_proof_must_agree(self):
        for key in ('offset', 'base', 'width', 'gap', 'partial', 'scope'):
            g = copy.deepcopy(self.graph)
            v = g['call_input_origins'][0]['chain'][0]['source']
            if key == 'offset': v['load']['displacement'] = 11
            if key == 'base': v['load']['base'] = 2
            if key == 'width': v['kind'] = 'load'
            if key == 'gap': v['proof'].pop(1)
            if key == 'partial': g['call_input_origins'][0]['chain'][0]['stop'] = 'call_barrier'
            if key == 'scope': g['call_input_origins'][0]['condition'] = 'unconditional'
            with self.subTest(key=key), self.assertRaises(AssertionError):
                check_field_inputs(g)

    def test_load_base_is_a_different_value(self):
        self.origin['chain'][0]['relation'] = 'load_base'
        with self.assertRaises(AssertionError):
            check_field_inputs(self.graph)

    def test_extreme_span_is_refused_before_expansion(self):
        self.origin['site'] = 1 << 60
        self.graph['edges'][0]['site'] = self.origin['site']
        self.origin['chain'][0]['source']['proof'][-1] = self.origin['site']
        with self.assertRaises(AssertionError):
            check_field_inputs(self.graph)

    def test_supplied_stack_location(self):
        self.origin.update(role='supplied_input', index=0, register=None, sp_offset=16)
        self.graph['call_input_shapes'] = [dict(site=0x1014, payload=0x1000, target=0x2000, count=3, word_bytes=8)]
        self.assertEqual(check_field_inputs(self.graph), 1)
        self.assertIn('supplied input[0] (SP+0x10)', render(query(self.graph, 0x1014)))
        self.origin['sp_offset'] = 8
        with self.assertRaises(AssertionError):
            check_field_inputs(self.graph)

    def test_async_operand_role(self):
        self.origin.update(role='completion_operand', register=0)
        self.graph['edges'][0]['kind'] = 'jump'
        self.graph['async_contracts'] = [dict(entry=0x2000, operation='complete_value')]
        self.assertEqual(check_field_inputs(self.graph), 1)
        self.assertIn('async completion operand (X0)', render(query(self.graph, 0x1014)))

    def test_source_condition_is_retained(self):
        self.graph['await_future_bindings'][0]['conditions'] = []
        with self.assertRaises(AssertionError):
            query(self.graph, 0x1014)

    def test_forged_links_and_counters(self):
        for key, value in [('context', 9), ('access', 9), ('input_origin', 9), ('scope', 'unconditional')]:
            g = copy.deepcopy(self.graph)
            g['async_field_input_links'][0][key] = value
            with self.subTest(key=key), self.assertRaises(AssertionError):
                check_field_inputs(g)
        self.graph['async_field_input_work']['remaining'] -= 1
        with self.assertRaises(AssertionError):
            check_field_inputs(self.graph)

    def test_comment_attachment_and_escaping(self):
        text = '// ' + note(self.graph, self.link, {7: 'Example"\n'}) + '\n'
        insn = '// 0x1014: bl 0x2000\n'
        self.assertIn('\\u000a', text)
        self.assertEqual(sum(check_stream(self.graph, [text, insn], {7: 'Example"\n'}).values()), 1)
        for lines in [[text], [insn], [text, text, insn], [text, insn, text, insn],
                      [text.replace('field value/type unknown', 'type bool'), insn]]:
            with self.assertRaises(AssertionError):
                check_stream(self.graph, lines)

    def test_plain_compact_gzip(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / 'snapshot_calls.json'
            gz = Path(str(p) + '.gz')
            g = dict(self.graph, export=dict(detail='compact', omitted=[]))
            p.write_text(json.dumps(g))
            with gzip.open(gz, 'wt') as f: json.dump(g, f)
            self.assertEqual(query(load_graph(p), 0x1014), query(load_graph(gz), 0x1014))


if __name__ == '__main__':
    unittest.main()
