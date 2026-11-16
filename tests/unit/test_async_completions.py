import copy
import gzip
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
from graph_io import load_graph
from query_async_completions import query, render


class CompletionPresentationTests(unittest.TestCase):
    def setUp(self):
        self.row = dict(payload=0x1000, status='exact_heap_class', exact_class=7,
                        entries=[0x1000], exits=[], completions=[dict(site=0x1008,
                        value='heap_class', class_id=7, basis='allocation', operation='complete_value')])
        self.graph = dict(format=37, completion_summaries=[self.row])

    def test_exact_value_has_explicit_scope(self):
        text = render(query(self.graph, 0x1000))
        self.assertIn('Successful direct value completions supply heap class 0x7', text)
        self.assertIn('No ordinary-return type, Future identity or producer-to-await binding', text)

    def test_forwarding_keeps_observed_operand_separate(self):
        row = copy.deepcopy(self.row)
        row.update(status='value_or_future', exact_class=None)
        row['completions'][0]['operation'] = 'complete_value_or_future'
        text = render(row)
        self.assertIn('X0 -> heap class 0x7', text)
        self.assertIn('local normal fallthrough', text)
        self.assertNotIn('Successful direct value completions supply', text)

    def test_missing_payload(self):
        with self.assertRaises(ValueError):
            query(self.graph, 0x2000)

    def test_legacy_graph(self):
        with self.assertRaises(ValueError):
            query(dict(format=36), 0x1000)

    def test_plain_and_gzip_agree(self):
        with tempfile.TemporaryDirectory() as temp:
            plain = Path(temp) / 'snapshot_calls.json'
            zipped = Path(str(plain)+'.gz')
            plain.write_text(json.dumps(self.graph))
            with gzip.open(zipped, 'wt') as stream:
                json.dump(self.graph, stream)
            self.assertEqual(query(load_graph(plain), 0x1000), query(load_graph(zipped), 0x1000))
            plain.unlink()
            self.assertEqual(query(load_graph(temp), 0x1000), self.row)

    def test_unknown_and_null_are_distinct(self):
        row = copy.deepcopy(self.row)
        row.update(status='null_only', exact_class=None)
        row['completions'][0].update(value='null', class_id=1, basis='sdk_null_register')
        text = render(row)
        self.assertIn('X0 -> null', text)
        self.assertNotIn('supply heap class', text)


if __name__ == '__main__':
    unittest.main()
