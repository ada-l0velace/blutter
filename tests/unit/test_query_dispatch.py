"""Authored dispatch-query cases; no application fixtures or runtime required."""
import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
from query_dispatch import query


class DispatchQuery(unittest.TestCase):
    def setUp(self):
        self.graph = {'dispatch_table': {'origin': 4, 'entries': [0x1000, 0x1004, None, 0x2000], 'null_target': 0x2000},
                      'nodes': [{'start': 0x1000, 'end': 0x1010, 'label': 'fixture'}],
                      'edges': [{'site': 0x3000, 'via_kind': 'dispatch_table', 'via_offset': 0,
                                 'dispatch': {'index': -4, 'expression': {'width': 20, 'addend': -4}}}]}

    def test_known_index_and_payload_entry(self):
        result = query(self.graph, 0x3000)
        self.assertEqual((result['snapshot_target'], result['payload'], result['label']), (0x1000, 0x1000, 'fixture'))
        self.assertEqual(result['index_source'], 'analyzed_constant')

    def test_supplied_value_is_explicit_and_preserves_graph(self):
        before = copy.deepcopy(self.graph)
        result = query(self.graph, 0x3000, extracted_value=1)
        self.assertEqual((result['index'], result['table_index'], result['snapshot_target']), (-3, 1, 0x1004))
        self.assertEqual(result['index_source'], 'supplied_extracted_value')
        self.assertEqual(self.graph, before)

    def test_null_and_unmapped_entries(self):
        self.assertTrue(query(self.graph, 0x3000, index=-1)['null_error_entry'])
        self.assertIsNone(query(self.graph, 0x3000, index=-2)['snapshot_target'])

    def test_bad_values_and_sites(self):
        for kwargs in ({'index': -5}, {'index': 0}, {'index': 1 << 63}, {'extracted_value': -1},
                       {'extracted_value': 1 << 20}, {'index': 0, 'extracted_value': 0}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                query(self.graph, 0x3000, **kwargs)
        with self.assertRaises(ValueError):
            query(self.graph, 0x3004)
        self.graph['edges'][0]['dispatch']['index'] = None
        with self.assertRaises(ValueError):
            query(self.graph, 0x3000)

    def test_missing_expression_and_misaligned_base(self):
        self.graph['edges'][0]['dispatch']['expression'] = None
        with self.assertRaises(ValueError):
            query(self.graph, 0x3000, extracted_value=1)
        self.graph['edges'][0]['via_offset'] = 1
        with self.assertRaises(ValueError):
            query(self.graph, 0x3000)


if __name__ == '__main__':
    unittest.main()
