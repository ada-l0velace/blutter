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
from async_field_accesses import SCOPE, check_fields, check_stream, note
from query_async_fields import query, render
from graph_io import load_graph


class AsyncFieldTests(unittest.TestCase):
    def setUp(self):
        self.layout = dict(class_id=7, kind='instance', header=8, end=16, tag=1, slot_bytes=4,
            context_parent=0, context_data=0, excluded=[], unboxed=[],
            fields=[dict(offset=8, owner=7, name='enabled', declared_type='bool?')])
        self.access = dict(site=0x1008, base=0, register=1, bytes=4, offset=8,
                           access='read', kind='instance_slot', index=None)
        self.context = dict(payload=0x1000, source_await=0x1004, seed=0x1008, register=0,
            class_id=7, basis='await_delivery', status='control_boundary', steps=2,
            scope=SCOPE, accesses=[self.access])
        self.graph = dict(format=40, async_field_layouts=[self.layout], async_field_contexts=[self.context],
            async_field_work=dict(supported=True, limit=200000, local_limit=64, steps=2, remaining=199998),
            receiver_metadata=dict(null_class_id=1, entries=[]), saved_reference_contexts=[],
            future_binding_bodies=[dict(payload=0x1000, end=0x1010, handlers=[])],
            await_future_bindings=[dict(payload=0x1000, site=0x1004, resume_site=0x1008,
                status='conditional_delivery', value='heap_class', class_id=7, conditions=list(CONDITIONS))])
        self.audit = dict(instance_field_abi=[1, 4, 8, 99, 8, 16],
            instance_field_metadata=[[7, 16, -1, 0, 0, [[8, 'enabled', 'bool?']]]])
        self.raw = bytes.fromhex('1f2003d51f2003d5017040b8c0035fd6')
        self.read = lambda address, length: self.raw[address - 0x1000:address - 0x1000 + length]

    def test_original_byte_proof(self):
        self.assertEqual(check_fields(self.graph, self.audit, self.read), 1)

    def test_forged_fields(self):
        for key, value in [('offset', 12), ('base', 2), ('register', 3), ('access', 'write'), ('bytes', 8)]:
            g = copy.deepcopy(self.graph)
            g['async_field_contexts'][0]['accesses'][0][key] = value
            with self.subTest(key=key), self.assertRaises(AssertionError):
                check_fields(g, self.audit, self.read)

    def test_lost_conditional_origin(self):
        for key, value in [('seed', 0x1000), ('scope', 'unconditional'), ('class_id', 8)]:
            g = copy.deepcopy(self.graph)
            g['async_field_contexts'][0][key] = value
            with self.subTest(key=key), self.assertRaises(AssertionError):
                check_fields(g, self.audit, self.read)

    def test_typed_layout_is_required(self):
        for key, value in [('tag', 0), ('end', 24), ('unboxed', [8]), ('fields', [])]:
            g = copy.deepcopy(self.graph)
            g['async_field_layouts'][0][key] = value
            with self.subTest(key=key), self.assertRaises(AssertionError):
                check_fields(g, self.audit, self.read)

    def test_query_is_identity_only(self):
        text = render(query(self.graph, 0x1008))
        self.assertIn('[conditional]', text)
        self.assertIn('field value', text)
        self.assertIn('declared_type', text)
        g = copy.deepcopy(self.graph)
        g['async_field_contexts'][0]['scope'] = 'unconditional'
        with self.assertRaises(ValueError):
            query(g, 0x1008)

    def test_comment_attachment(self):
        text = '// ' + note(self.context, self.access, self.layout) + '\n'
        instruction = '// 0x1008: ldur w1, [x0, #7]\n'
        self.assertEqual(sum(check_stream(self.graph, [text, instruction]).values()), 1)
        for lines in [[text], [instruction], [text, text, instruction], [text, instruction, text, instruction],
                      [text.replace('field value unknown', 'value true'), instruction]]:
            with self.assertRaises(AssertionError):
                check_stream(self.graph, lines)

    def test_escaped_metadata(self):
        self.layout['fields'][0]['name'] = 'quoted"\nname'
        text = note(self.context, self.access, self.layout)
        self.assertNotIn('\n', text)
        self.assertIn('\\u000a', text)
        self.assertEqual(sum(check_stream(self.graph, ['// ' + text + '\n', '// 0x1008: ldur\n']).values()), 1)

    def test_restored_seed_requires_parent_scope(self):
        self.context['basis'] = 'restored_reference'
        parent = dict(payload=0x1000, source_await=0x1004, class_id=7, status='checked',
            scope='conditional_saved_reference_only', observations=[dict(site=0x1004, register=0)])
        self.graph['saved_reference_contexts'] = [parent]
        self.assertEqual(len(query(self.graph, 0x1008)), 1)
        parent['scope'] = 'unconditional'
        with self.assertRaises(AssertionError):
            query(self.graph, 0x1008)

    def test_optional_vm_display_names(self):
        text = '// ' + note(self.context, self.access, self.layout, {7: 'VMImplementation'}) + '\n'
        instruction = '// 0x1008: ldur w1, [x0, #7]\n'
        self.assertEqual(sum(check_stream(self.graph, [text, instruction], {}).values()), 1)
        with self.assertRaises(AssertionError):
            check_stream(self.graph, [text, instruction], {7: 'Different'})

    def test_plain_compact_gzip(self):
        with tempfile.TemporaryDirectory() as temp:
            p = Path(temp) / 'snapshot_calls.json'
            gz = Path(str(p) + '.gz')
            graph = dict(self.graph, export=dict(detail='compact', omitted=[]))
            p.write_text(json.dumps(graph))
            with gzip.open(gz, 'wt') as f:
                json.dump(graph, f)
            self.assertEqual(query(load_graph(p), 0x1008), query(load_graph(gz), 0x1008))
            p.unlink()
            self.assertEqual(query(load_graph(temp), 0x1008), query(self.graph, 0x1008))


if __name__ == '__main__':
    unittest.main()
