import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
from query_stack_inputs import query, render_text


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

    def add_traces(self):
        self.graph['format'] = 22
        self.graph['nodes'] += [
            {'start': 0x3000, 'end': 0x3024, 'label': 'helper container',
             'names': [{'address': 0x3018, 'kind': 'function', 'name': 'length_entry'}]},
            {'start': 0x3500, 'end': 0x3520, 'label': 'getter'},
            {'start': 0x4000, 'end': 0x4020, 'label': 'shared container', 'names': [
                {'address': 0x4000, 'kind': 'function', 'name': 'different_entry'},
                {'address': 0x4004, 'kind': 'function', 'name': 'shared_a'},
                {'address': 0x4004, 'kind': 'function', 'name': 'shared_b'}]}]
        self.graph['call_effects'] = [{'payload': 0x3500, 'array_return': {
            'array_sp_offset': 8, 'index_sp_offset': 0, 'index_min': 0, 'index_max': 31, 'states': [[0x3500, []]]}}]
        self.graph['prefix_call_effects'] = [{'payload': 0x3018, 'containing_payload': 0x3000, 'array_length': {
            'array_sp_offset': 0, 'heap_effect': 'read_only', 'proof': [0x3018, 0x301c, 0x3020]}}]
        path = {'edge': 'fallthrough', 'site': 0x2000, 'successor': 0x2004,
                'slow_path': 0x201c, 'stub': 0x6000, 'proof': [0x2000]}
        context = {'payload': 0x2000, 'callers': [0x1010], 'scope': 'entry_result_use', 'status': 'result_dispatch_proved',
                   'inputs': [{'sp_offset': 0, 'kind': 'heap_class', 'value': '0x2'},
                              {'sp_offset': 8, 'kind': 'word', 'value': '0x4'}],
                   'array_input': {'sp_offset': 0, 'length': 2, 'elements': [[0, 7], [1, 8]]},
                   'path_condition': path, 'array_reads': [],
                   'array_length_returns': [{'site': 0x2004, 'callee': 0x3018, 'register': 'x0',
                                            'length': 2, 'value': '0x4', 'allocation': None, 'proof': [0x2004]}],
                   'indexed_returns': [{'site': 0x2008, 'callee': 0x3500, 'index': 0, 'class_id': 7,
                                        'register': 'x0', 'entry_input_sp_offset': 0, 'proof': [0x2008]}],
                   'resolutions': [{'site': 0x2018, 'load': 0x2014, 'snapshot_target': 0x4004, 'proof': [0x2014]}],
                   'trace': {'blocks': [0x2000, 0x2004, 0x2008, 0x200c], 'getter': 0x2008, 'stop': 0x2018,
                             'stack_checks': [dict(path, site=0x2004, successor=0x2008)]},
                   'certificate': {'payload': 0x2000, 'blocks': [{'states': [[0x2000, []]]}]}}
        self.graph['array_result_traces'] = [context]
        return context

    def test_scoped_collections_remain_distinct(self):
        result_use = self.add_traces()
        first_getter = copy.deepcopy(result_use)
        first_getter.update(scope='entry_prefix', status='indexed_result_proved')
        first_getter['trace'].pop('getter')
        first_getter['trace']['stop'] = 0x2008
        first_getter['resolutions'] = []
        length_path = copy.deepcopy(first_getter)
        length_path.update(scope='initial_stack_check_fast_path', status='length_proved', indexed_returns=[])
        length_path.pop('trace')
        self.graph['array_entry_traces'] = [first_getter]
        self.graph['array_path_contexts'] = [length_path]
        result = query(self.graph, 0x2000)
        shown = result['calls'][0]['array_traces']
        self.assertEqual([c['scope'] for c in shown], ['initial_stack_check_fast_path', 'entry_prefix', 'entry_result_use'])
        self.assertEqual(list(result['array_trace_counts'].values()), [1, 1, 1])
        self.assertIsNone(shown[0]['trace'])
        self.assertEqual(shown[0]['indexed_returns'], [])
        self.assertEqual(shown[2]['trace']['getter'], '0x2008')
        self.assertEqual(result['calls'][1]['array_traces'], [])

    def test_caller_filter_keeps_conflicting_contexts_separate(self):
        first = self.add_traces()
        second = copy.deepcopy(first)
        second['callers'] = [0x1014]
        second['array_input']['elements'][0][1] = 8
        second['indexed_returns'][0]['class_id'] = 8
        second['resolutions'][0]['snapshot_target'] = 0x4008
        self.graph['array_result_traces'].append(second)
        result = query(self.graph, 0x2000, caller=0x1010)
        self.assertEqual(result['caller_count'], 2)
        self.assertEqual(result['selected_caller_count'], 1)
        self.assertEqual(result['shown_caller_count'], 1)
        self.assertEqual(result['callers_with_array_traces'], 2)
        self.assertEqual(result['array_trace_counts']['array_result_traces'], 2)
        shown = result['calls'][0]['array_traces']
        self.assertEqual(len(shown), 1)
        self.assertEqual(shown[0]['indexed_returns'][0]['class_id'], 7)
        self.assertEqual(shown[0]['dispatches'][0]['snapshot_target'], '0x4004')

    def test_legacy_contexts_do_not_overwrite_filter(self):
        self.add_traces()
        self.graph['call_contexts'] = [{'payload': 0x2000, 'callers': [0x1014], 'resolutions': []}]
        self.graph['array_contexts'] = [{'payload': 0x2000, 'callers': [0x1014], 'scope': 'entry_block',
                                       'status': 'bound_only', 'array_input': {'sp_offset': 0, 'length': 1, 'elements': [[0, 8]]},
                                       'array_reads': [], 'resolutions': []}]
        result = query(self.graph, 0x2000, caller=0x1010)
        self.assertEqual(result['caller_filter'], '0x1010')
        self.assertEqual(result['calls'][0]['site'], '0x1010')
        self.assertIsNone(query(self.graph, 0x2000)['caller_filter'])
        self.assertIn('Ordinary array context: entry_block / bound_only', render_text(query(self.graph, 0x2000)))

    def test_trace_totals_survive_display_limit(self):
        context = self.add_traces()
        context['callers'].append(0x1014)
        result = query(self.graph, 0x2000, 1)
        self.assertEqual(result['array_trace_counts']['array_result_traces'], 1)
        self.assertEqual(result['callers_with_array_traces'], 2)
        self.assertEqual(result['selected_caller_count'], 2)
        self.assertEqual(result['shown_caller_count'], 1)

    def test_multiple_array_bindings_are_not_merged(self):
        context = self.add_traces()
        other = copy.deepcopy(context)
        other['array_input']['sp_offset'] = 8
        self.graph['array_result_traces'].append(other)
        shown = query(self.graph, 0x2000)['calls'][0]['array_traces']
        self.assertEqual([c['array_input']['sp_offset'] for c in shown], [0, 8])
        self.assertEqual(shown[0]['inputs'][1], {'sp_offset': 8, 'kind': 'word', 'value': '0x4'})

    def test_scoped_results_do_not_become_legacy_results(self):
        self.add_traces()
        result = query(self.graph, 0x2000)
        call = result['calls'][0]
        self.assertEqual(call['context_dispatches'], [])
        self.assertEqual(call['array_contexts'], [])
        self.assertIsNone(call['indexed_return'])
        self.assertIsNone(result['array_result'])
        interior = query(self.graph, 0x2004)
        self.assertFalse(interior['mapping_available'])
        self.assertEqual(interior['calls'][0]['array_traces'], [])

    def test_helper_entry_container_and_physical_relation_are_shown(self):
        self.add_traces()
        shown = query(self.graph, 0x2000)['calls'][0]['array_traces'][0]
        length = shown['length_returns'][0]
        self.assertEqual(length['callee'], '0x3018')
        self.assertEqual(length['callee_info']['containing_payload'], '0x3000')
        self.assertEqual(length['effect_collection'], 'prefix_call_effects')
        self.assertEqual(length['callee_relation'], {'array_sp_offset': 0, 'heap_effect': 'read_only'})
        getter = shown['indexed_returns'][0]
        self.assertEqual(getter['effect_collection'], 'call_effects')
        self.assertEqual(getter['callee_relation']['array_sp_offset'], 8)
        self.assertEqual(getter['callee_relation']['index_sp_offset'], 0)

    def test_initial_path_cannot_inherit_supplemental_effects(self):
        context = self.add_traces()
        path = copy.deepcopy(context)
        path.update(scope='initial_stack_check_fast_path', status='length_proved', indexed_returns=[], resolutions=[])
        path.pop('trace')
        self.graph['array_path_contexts'] = [path]
        shown = query(self.graph, 0x2000)['calls'][0]['array_traces']
        self.assertIsNone(shown[0]['length_returns'][0]['callee_relation'])
        self.assertEqual(shown[1]['length_returns'][0]['effect_collection'], 'prefix_call_effects')
        self.graph['call_effects'].append(copy.deepcopy(self.graph['prefix_call_effects'][0]))
        shown = query(self.graph, 0x2000)['calls'][0]['array_traces']
        self.assertEqual(shown[0]['length_returns'][0]['effect_collection'], 'call_effects')

    def test_entry_aliases_are_distinct_from_container_label(self):
        self.add_traces()
        info = query(self.graph, 0x2000)['calls'][0]['array_traces'][0]['dispatches'][0]['target_info']
        self.assertEqual(info['entry'], '0x4004')
        self.assertEqual(info['containing_payload'], '0x4000')
        self.assertEqual(info['payload_label'], 'shared container')
        self.assertEqual([v['name'] for v in info['entry_names']], ['shared_a', 'shared_b'])

    def test_summaries_omit_invariants_and_do_not_mutate_graph(self):
        self.add_traces()
        before = copy.deepcopy(self.graph)
        result = query(self.graph, 0x2000)
        render_text(result)
        self.assertEqual(self.graph, before)
        def inspect(value):
            if isinstance(value, dict):
                self.assertFalse({'proof', 'certificate', 'states'} & value.keys())
                for v in value.values(): inspect(v)
            elif isinstance(value, list):
                for v in value: inspect(v)
        inspect(result['calls'][0]['array_traces'])

    def test_unmapped_target_and_missing_relation_remain_unknown(self):
        context = self.add_traces()
        context['resolutions'][0]['snapshot_target'] = 0x9000
        self.graph['prefix_call_effects'] = []
        shown = query(self.graph, 0x2000)['calls'][0]['array_traces'][0]
        self.assertIsNone(shown['dispatches'][0]['target_info']['containing_payload'])
        self.assertEqual(shown['dispatches'][0]['target_info']['entry_names'], [])
        self.assertIsNone(shown['length_returns'][0]['effect_collection'])
        self.assertIsNone(shown['length_returns'][0]['callee_relation'])
        text = render_text(query(self.graph, 0x2000))
        self.assertIn('effect collection unavailable', text)
        self.assertIn('Dispatch 0x2018 -> 0x9000 (containing payload unknown)', text)

    def test_path_read_does_not_invent_a_getter_result(self):
        context = self.add_traces()
        context.update(scope='initial_stack_check_fast_path', status='read_proved', indexed_returns=[], resolutions=[])
        context.pop('trace')
        context['array_reads'] = [{'site': 0x2008, 'index': 0, 'class_id': 7, 'register': 'x2'}]
        self.graph['array_path_contexts'] = self.graph.pop('array_result_traces')
        text = render_text(query(self.graph, 0x2000))
        self.assertIn('Array read 0x2008: index=0 -> x2 class 7', text)
        self.assertNotIn('Getter ', text)

    def test_payload_label_does_not_invent_an_entry_name(self):
        self.add_traces()
        self.graph['nodes'][-1].pop('names')
        text = render_text(query(self.graph, 0x2000))
        self.assertIn('Payload label: shared container', text)
        self.assertNotIn('Metadata entry names:', text)

    def test_other_callee_contexts_do_not_attach(self):
        context = self.add_traces()
        context['payload'] = 0x3000
        result = query(self.graph, 0x2000)
        self.assertEqual(result['callers_with_array_traces'], 0)
        self.assertEqual(result['calls'][0]['array_traces'], [])

    def test_text_shows_conditions_results_and_entry_names(self):
        self.add_traces()
        text = render_text(query(self.graph, 0x2000, caller=0x1010))
        for expected in ('Caller 0x1010', 'entry_result_use / result_dispatch_proved',
                         'Input conditions: SP+0 heap_class=0x2, SP+8 word=0x4',
                         'Initial stack condition: fallthrough', 'Additional stack condition: fallthrough',
                         'index=0 -> x0 class 7', 'Dispatch 0x2018 -> 0x4004',
                         'Helper entry 0x3018; containing payload 0x3000',
                         'function: shared_a; function: shared_b', 'normal return'):
            self.assertIn(expected, text)
        self.assertNotIn('different_entry', text)
        self.assertNotIn('Caller 0x1014', text)

    def test_legacy_graph_has_no_synthesized_traces(self):
        result = query(self.graph, 0x2000)
        self.assertEqual(list(result['array_trace_counts'].values()), [0, 0, 0])
        self.assertIn('Scoped array traces: none recorded', render_text(result))
        self.assertNotIn('Getter ', render_text(result))

    def test_unresolved_array_shows_only_known_later_elements(self):
        self.graph['array_contexts'] = [{'payload': 0x2000, 'callers': [0x1010], 'scope': 'entry_block',
            'status': 'bound_only', 'array_input': {'sp_offset': 0, 'length': 2, 'elements': [[1, 8]]},
            'array_reads': [], 'resolutions': []}]
        before = copy.deepcopy(self.graph)
        text = render_text(query(self.graph, 0x2000, caller=0x1010))
        self.assertIn('length=2; known elements: [1]=class 8', text)
        self.assertIn('entry_block / bound_only', text)
        self.assertIn('Scoped array traces: none recorded', text)
        self.assertNotIn('[0]=class', text)
        self.assertNotIn('Getter ', text)
        self.assertEqual(self.graph, before)

    def test_invalid_caller_filter(self):
        for caller in (0x1018, 0x2000, 0, '0x1010', True):
            with self.subTest(caller=caller), self.assertRaises(ValueError):
                query(self.graph, 0x2000, caller=caller)

    def test_cli_default_json_text_and_filter_error(self):
        self.add_traces()
        script = Path(__file__).resolve().parents[2] / 'scripts/query_stack_inputs.py'
        with tempfile.TemporaryDirectory() as temporary:
            graph = Path(temporary) / 'graph.json'
            graph.write_text(json.dumps(self.graph))
            command = [sys.executable, str(script), str(graph), '--target', '0x2000', '--caller', '0x1010']
            default = subprocess.run(command, text=True, capture_output=True, check=True)
            self.assertEqual(json.loads(default.stdout)['caller_filter'], '0x1010')
            text = subprocess.run(command+['--format', 'text'], text=True, capture_output=True, check=True)
            self.assertIn('Dispatch 0x2018 -> 0x4004', text.stdout)
            failed = subprocess.run(command[:-1]+['0x1018'], text=True, capture_output=True)
            self.assertEqual(failed.returncode, 2)
            self.assertIn('direct call instruction', failed.stderr)


if __name__ == '__main__':
    unittest.main()
