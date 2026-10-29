import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
from query_stack_inputs import query


class StackQuery(unittest.TestCase):
    def setUp(self):
        self.graph = {'format': 5, 'nodes': [
            {'start': 0x1000, 'end': 0x1020, 'label': 'caller'},
            {'start': 0x2000, 'end': 0x2020, 'label': 'callee'}],
            'edges': [{'site': 0x1010, 'source': 0x1000, 'kind': 'call', 'target': 0x2000,
                       'stack_inputs': [{'sp_offset': 0, 'kind': 'word', 'value': '0x1', 'proof': [0x100c]}]},
                      {'site': 0x1014, 'source': 0x1000, 'kind': 'call', 'target': 0x2000, 'stack_inputs': []},
                      {'site': 0x1018, 'source': 0x1000, 'kind': 'call', 'target': 0x2004,
                       'stack_inputs': [{'sp_offset': 0, 'kind': 'word', 'value': '0x2', 'proof': [0x1014]}]}],
            'entry_stack_loads': [{'site': 0x200c, 'payload': 0x2000, 'entry_sp_offset': 0,
                                   'register': 'x2', 'width': 8, 'proof': [0x2008, 0x200c]}]}

    def test_exact_entry_mapping_and_partial_callers(self):
        result = query(self.graph, 0x2000)
        self.assertEqual(result['caller_count'], 2)
        self.assertEqual(result['callers_with_observations'], 1)
        self.assertEqual(result['calls'][0]['stack_inputs'][0]['callee_loads'][0]['register'], 'x2')
        self.assertFalse(result['calls'][1]['stack_inputs'])

    def test_interior_entries_do_not_inherit_frame_mapping(self):
        result = query(self.graph, 0x2004)
        self.assertFalse(result['mapping_available'])
        self.assertFalse(result['calls'][0]['stack_inputs'][0]['callee_loads'])

    def test_display_limit_does_not_change_total(self):
        result = query(self.graph, 0x2000, 1)
        self.assertEqual(len(result['calls']), 1)
        self.assertEqual(result['caller_count'], 2)

    def test_context_targets_stay_with_their_checked_caller(self):
        graph = copy.deepcopy(self.graph)
        graph['format'] = 6
        graph['call_contexts'] = [{'payload': 0x2000, 'callers': [0x1010],
            'resolutions': [{'site': 0x2010, 'load': 0x200c, 'index': 1, 'table_index': 1,
                             'snapshot_target': 0x1000, 'proof': [0x2008, 0x200c]}]}]
        result = query(graph, 0x2000)
        self.assertEqual(result['callers_with_context_dispatches'], 1)
        self.assertEqual(result['calls'][0]['context_dispatches'][0]['snapshot_target_label'], 'caller')
        self.assertFalse(result['calls'][1]['context_dispatches'])

    def test_invalid_inputs(self):
        for limit in (0, 1001):
            with self.assertRaises(ValueError):
                query(self.graph, 0x2000, limit)
        with self.assertRaises(ValueError):
            query(self.graph, 0x3000)
        old = copy.deepcopy(self.graph)
        old['format'] = 4
        with self.assertRaises(ValueError):
            query(old, 0x2000)


if __name__ == '__main__':
    unittest.main()
