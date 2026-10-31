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

    def test_array_context_binding_is_distinct_from_a_read(self):
        self.graph['format'] = 15
        context = {'payload': 0x2000, 'callers': [0x1010], 'scope': 'entry_block', 'status': 'bound_only',
                   'array_input': {'sp_offset': 0, 'length': 2, 'elements': [[0, 1]]},
                   'array_reads': [], 'resolutions': [], 'certificate': None}
        self.graph['array_contexts'] = [context]
        result = query(self.graph, 0x2000)
        self.assertEqual(result['array_context_count'], 1)
        self.assertEqual(result['callers_with_array_contexts'], 1)
        self.assertEqual(result['array_context_reads'], 0)
        self.assertEqual(result['calls'][0]['array_contexts'][0]['status'], 'bound_only')
        self.assertEqual(result['calls'][1]['array_contexts'], [])

    def test_array_context_query_displays_proved_reads(self):
        self.graph['format'] = 15
        self.graph['array_contexts'] = [{'payload': 0x2000, 'callers': [0x1010], 'scope': 'entry_block', 'status': 'read_proved',
            'array_input': {'sp_offset': 0, 'length': 2, 'elements': [[0, 1]]},
            'array_reads': [{'site': 0x2008, 'input_sp_offset': 0, 'index': 0, 'class_id': 1, 'register': 'x2', 'proof': [0x2008]}],
            'resolutions': [], 'certificate': {'payload': 0x2000}}]
        result = query(self.graph, 0x2000)
        self.assertEqual(result['array_context_reads'], 1)
        shown = result['calls'][0]['array_contexts'][0]
        self.assertEqual(shown['reads'][0]['site'], '0x2008')
        self.assertNotIn('certificate', shown)

    def test_conditional_array_result_does_not_publish_invariants(self):
        self.graph['format'] = 14
        relation = {'array_sp_offset': 8, 'index_sp_offset': 0, 'index_representation': 'smi',
                    'index_min': 0, 'index_max': 31, 'states': [[0x2000, []]]}
        self.graph['call_effects'] = [{'payload': 0x2000, 'array_return': relation}]
        result = query(self.graph, 0x2000)
        self.assertEqual(result['array_result'], {k: v for k, v in relation.items() if k != 'states'})
        self.assertIsNone(result['calls'][0]['indexed_return'])

    def test_exact_entry_mapping_and_partial_callers(self):
        result = query(self.graph, 0x2000)
        self.assertEqual(result['caller_count'], 2)
        self.assertEqual(result['callers_with_observations'], 1)
        self.assertEqual(result['calls'][0]['stack_inputs'][0]['callee_loads'][0]['register'], 'x2')
        self.assertFalse(result['calls'][1]['stack_inputs'])

    def test_result_forwarding_and_return_only_context_are_visible(self):
        self.graph['format'] = 12
        self.graph['receiver_metadata'] = {'word_return_register': 'x0'}
        self.graph['call_effects'] = [{'payload': 0x2000, 'return_input': 0}]
        self.graph['call_contexts'] = [{'payload': 0x2000, 'callers': [0x1010], 'resolutions': [],
                                      'forwarded_returns': [{'site': 0x200c, 'callee': 0x3000, 'input_sp_offset': 0, 'class_id': 1}]}]
        result = query(self.graph, 0x2000)
        self.assertEqual(result['result_forwarding'], {'register': 'x0', 'input_sp_offset': 0})
        self.assertEqual(result['callers_with_context_dispatches'], 0)
        self.assertEqual(result['callers_with_context_forwarded_returns'], 1)
        self.assertEqual(result['calls'][0]['context_forwarded_returns'][0]['callee'], '0x3000')

    def test_partial_array_arguments_are_visible(self):
        self.graph['edges'][0]['array_arguments'] = [{'sp_offset': 0, 'allocation': 0x1004, 'length': 2, 'elements': [[0, 1]]}]
        result = query(self.graph, 0x2000)
        self.assertEqual(result['callers_with_array_arguments'], 1)
        argument = result['calls'][0]['array_arguments'][0]
        self.assertEqual(argument['allocation'], '0x1004')
        self.assertEqual(argument['elements'], [[0, 1]])

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
