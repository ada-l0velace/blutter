"""Certificate joins preserve identity, alternatives, conditions and unknowns."""
import copy
import gzip
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import test_callee_entry_reads as entry_fixture
from async_future_bindings import CONDITIONS
from graph_io import load_graph
from field_input_origins import expected
from query_value_trails import query, render


class ValueTrailsTests(unittest.TestCase):
    def setUp(self):
        f = entry_fixture.CalleeEntryReadsTests();f.setUp();self.g = f.g
        c = self.g['async_field_contexts'][0]
        c.update(register=0, steps=2, status='registers_lost', scope='conditional_layout_only')
        c['accesses'][0].update(kind='instance_slot', index=None)
        self.g['receiver_metadata']['null_class_id'] = 1
        self.g.update(await_future_bindings=[dict(site=c['source_await'], payload=c['payload'], resume_site=c['seed'],
            status='conditional_delivery', value='heap_class', class_id=c['class_id'], conditions=list(CONDITIONS))],
            saved_reference_contexts=[], call_input_origins=[], call_input_shapes=[], stub_input_contracts=[],
            async_contracts=[], call_input_abi=dict(supported=True, word_bytes=8), async_field_input_links=[],
            async_field_input_work=dict(limit=200000, link_limit=4096, origins_examined=0, candidates=0, remaining=200000, complete=True))
        self.g['async_field_layouts'] = [dict(self.g['fresh_field_layouts'][0], fields=[])]

    def test_complete_trail_joins_exact_parents(self):
        rows = query(self.g)
        self.assertEqual(len(rows), 1)
        r = rows[0]['captures'][0]['reloads'][0]
        f = r['initializations'][0];c = f['contents'][0];e = c['entry_reads'][0]
        self.assertEqual((r['site'], f['write']['site'], c['transfer'], e['read']['site']), (0x1010, 0x1014, 0x101c, 0x2000))
        self.assertEqual(e['callee'], 0x2000)
        self.assertIn('source parameter position/type', e['text'])

    def test_every_recorded_milestone_selects_same_trail(self):
        all_rows = query(self.g)
        for site in [0xffc, 0x1000, 0x1008, 0x100c, 0x1010, 0x1014, 0x101c, 0x2000]:
            with self.subTest(site=site):self.assertEqual(query(self.g, site), all_rows)
        self.assertEqual(query(self.g, 0x1234), [])
        self.assertEqual(query(self.g, payload=0x1000), all_rows)
        self.assertEqual(query(self.g, payload=0x2000), [])

    def test_conditions_and_boundaries_are_visible(self):
        text = render(query(self.g));detailed = render(query(self.g), evidence=True)
        for token in ['normal_producer_return', 'successful_await_resume', 'normal allocation return',
                'first write only', 'selected contents at transfer only', 'selected contents at this read only',
                'decision predicate', 'external sink']:
            with self.subTest(token=token):self.assertIn(token, text)
        self.assertIn('container consumer:', detailed)
        self.assertNotIn('container consumer:', text)
        self.assertIn('captured value', text)

    def test_unknown_does_not_mean_no_external_behavior(self):
        self.assertIn('does not establish absence', render([]))
        self.assertIn('not established by these certificates', render(query(self.g)))

    def test_no_decision_or_sink_inferred_from_display_names(self):
        self.g['nodes'][1]['name'] = 'navigation_request_update'
        text = render(query(self.g))
        self.assertNotIn('navigation_request_update', text)
        self.assertIn('decision predicate; external sink', text)

    def test_role_proven_direct_input_is_separate(self):
        self.g['edges'].append(dict(site=0x100c, source=0x1000, target=0x2000, kind='call'))
        self.g['stub_input_contracts'] = [dict(entry=0x2000, inputs=[dict(register='x1', role='array_type_arguments')])]
        self.g['call_input_origins'] = [dict(site=0x100c, payload=0x1000, role='array_type_arguments', index=None,
            register=1, sp_offset=None, condition='normal_fallthrough', chain=[dict(relation='input', stop='load_endpoint',
                steps=3, pool_index=None, source=dict(kind='load_compressed', site=0x1000, load=dict(base=0, displacement=7, bytes=4), proof=[0x1000,0x1004,0x1008,0x100c]))])]
        links, work = expected(self.g);self.g.update(async_field_input_links=links, async_field_input_work=work)
        self.assertEqual(len(links), 1)
        self.assertIn('field input: array type arguments', render(query(self.g)))
        self.g['call_input_origins'][0]['role'] = 'register_observation'
        with self.assertRaises(AssertionError):query(self.g)

    def test_container_input_requires_its_own_role(self):
        self.g['container_entry_read_links'] = []
        self.g['call_input_origins'] = [dict(site=0x101c, payload=0x1000, role='register_observation', index=None, register=0, sp_offset=None, chain=[])]
        self.g['fresh_content_contexts'][0].update(status='matched_container_input', inputs=[0])
        self.g['async_field_input_work'].update(origins_examined=1)
        with self.assertRaisesRegex(ValueError, 'certified consumer input role'):query(self.g)

    def test_field_owner_source_must_be_conditional(self):
        for defect in ['scope', 'class', 'seed', 'condition']:
            g = copy.deepcopy(self.g)
            if defect == 'scope':g['async_field_contexts'][0]['scope'] = 'unconditional'
            elif defect == 'class':g['await_future_bindings'][0]['class_id'] += 1
            elif defect == 'seed':g['await_future_bindings'][0]['resume_site'] += 4
            else:g['await_future_bindings'][0]['conditions'] = []
            with self.subTest(defect=defect), self.assertRaises((AssertionError, ValueError)):query(g)

    def test_no_consumer_created_by_proximity(self):
        self.g['container_entry_read_links'] = []
        row = query(self.g)[0]
        c = row['captures'][0]['reloads'][0]['initializations'][0]['contents'][0]
        self.assertEqual(c['entry_reads'], [])
        self.assertNotIn('  consumer:', render([row]))

    def test_failed_capture_is_retained_as_boundary(self):
        self.g['captured_field_contexts'][0].update(reloads=[], status='control_boundary')
        self.g['fresh_field_contexts'] = []
        self.g['fresh_field_work'].update(steps=0, remaining=200000)
        self.g['fresh_content_contexts'] = []
        self.g['fresh_content_work'].update(steps=0, remaining=200000)
        self.g['container_entry_read_links'] = []
        self.assertIn('capture boundary: control_boundary', render(query(self.g)))

    def test_query_does_not_mutate_the_graph(self):
        before = copy.deepcopy(self.g);query(self.g);self.assertEqual(before, self.g)

    def test_same_read_with_distinct_delivery_sources_is_not_coalesced(self):
        c = copy.deepcopy(self.g['async_field_contexts'][0]);c['source_await'] = 0xff8
        self.g['async_field_contexts'].append(c)
        b = copy.deepcopy(self.g['await_future_bindings'][0]);b['site'] = 0xff8
        self.g['await_future_bindings'].append(b)
        c = copy.deepcopy(self.g['captured_field_contexts'][0]);c.update(context=1, steps=0, reloads=[])
        self.g['captured_field_contexts'].append(c)
        rows = query(self.g, 0x1000)
        self.assertEqual([r['source']['source_await'] for r in rows], [0xffc, 0xff8])
        self.assertEqual(len(query(self.g, 0x101c)), 1)

    def test_two_physical_inputs_remain_distinct(self):
        self.g['fresh_content_contexts'][0].update(steps=3, transfer=0x1020, proof=[0x1014,0x1018,0x101c,0x1020])
        self.g['fresh_content_work'].update(steps=3, remaining=199997)
        self.g['edges'][0]['site'] = 0x1020;self.g['nodes'][0]['end'] = 0x1024
        self.g['callee_entry_read_contracts'][0]['reads'].append(dict(site=0x2000, entry_sp_offset=8, register=2, part=1, bytes=8))
        self.g['container_entry_read_links'].append(dict(context=0, contract=0, read=1, scope='conditional_callee_entry_read'))
        rows = query(self.g, 0x1020);text = render(rows)
        self.assertIn('entry SP+0x0', text);self.assertIn('entry SP+0x8', text)
        self.assertNotIn('supplied input[', text)

    def test_formats_and_gzip_are_equivalent(self):
        with tempfile.TemporaryDirectory() as name:
            p = Path(name);rows = query(self.g)
            for detail in ['full', 'compact']:
                g = copy.deepcopy(self.g);g['export'] = dict(detail=detail, omitted=[] if detail=='full' else ['receiver_blocks','call_effect_states'])
                for compressed in [False, True]:
                    path = p/('graph.json.gz' if compressed else 'graph.json');raw = json.dumps(g).encode()
                    path.write_bytes(gzip.compress(raw) if compressed else raw)
                    self.assertEqual(query(load_graph(path)), rows)

    def test_older_format_rejected_explicitly(self):
        self.g['format'] = 44
        with self.assertRaisesRegex(ValueError, 'format 45'):query(self.g)

    def test_cli_errors_and_json(self):
        script = Path(__file__).resolve().parents[2]/'scripts/query_value_trails.py'
        with tempfile.TemporaryDirectory() as name:
            path = Path(name)/'graph.json';path.write_text(json.dumps(self.g))
            p = subprocess.run([sys.executable,str(script),str(path),'--site','0x101c','--json'],capture_output=True,text=True)
            self.assertEqual(p.returncode, 0, p.stderr);self.assertEqual(json.loads(p.stdout), query(self.g,0x101c))
            self.g['container_entry_read_links'][0]['scope'] = 'unconditional'
            path.write_text(json.dumps(self.g));p = subprocess.run([sys.executable,str(script),str(path)],capture_output=True,text=True)
            self.assertNotEqual(p.returncode, 0)
            self.assertNotIn('  consumer:',p.stdout)
            self.assertIn('Inconsistent value-trail certificate',p.stderr)


if __name__ == '__main__':unittest.main()
