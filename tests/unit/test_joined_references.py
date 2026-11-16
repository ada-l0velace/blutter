"""Independent original-word and scope controls for joined reference evidence."""
import copy
import gzip
import io
import json
from pathlib import Path
import tempfile
import unittest
from async_future_bindings import CONDITIONS
from graph_io import load_graph
from joined_async_references import LIMITS, SCOPE, check_joined, validate_structure, note, check_stream
from query_joined_references import query, render


class JoinedReferenceTests(unittest.TestCase):
    def setUp(self):
        self.words = [0x94000400, 0xf81f03a0, 0xb4000061, 0xaa1603e0,
            0x940003fc, 0xf85f03a2, 0xaa1603e0, 0x140007f9]
        self.o = dict(site=0x1014, store=0x1004, slot=-16, register=2, last_suspensions=[None,0x1010])
        self.c = dict(payload=0x1000, source_await=0x1000, class_id=7, scope=SCOPE, status='checked', steps=7, observations=[self.o])
        self.g = dict(format=46, joined_reference_contexts=[self.c], joined_reference_work=dict(LIMITS,steps=7,remaining=199993,history_overflows=0,bytes=32,complete=True),
            saved_reference_abi=dict(supported=True,first_local_offset=-8),future_binding_abi=dict(supported=True,suspend_state_offset=-8),
            receiver_metadata=dict(null_class_id=1,entries=[0x1000],nonreturning_calls=[]),
            saved_reference_contexts=[dict(payload=0x1000,source_await=0x1000,class_id=7,status='checked',observations=[])],
            saved_reference_frames=[dict(payload=0x1000,status='matched_async_frame',points=[[pc,-256,True] for pc in range(0x1000,0x1020,4)])],
            saved_reference_stack_maps=[dict(payload=0x1000,site=0x1010,available=True,spill_slots=32,objects=[-16])],
            nodes=[dict(start=0x1000,end=0x1020)],future_binding_bodies=[dict(payload=0x1000,handlers=[])],
            await_future_bindings=[dict(payload=0x1000,site=0x1000,resume_site=0x1004,status='conditional_delivery',value='heap_class',class_id=7,conditions=list(CONDITIONS))],
            async_contracts=[dict(entry=0x2000,operation='await'),dict(entry=0x3000,operation='complete_value')],completion_exception_contracts=[])
        self.audit = {k:copy.deepcopy(self.g[k]) for k in ('saved_reference_abi','saved_reference_stack_maps')}

    def read(self, address, size):
        raw=b''.join(w.to_bytes(4,'little') for w in self.words);off=address-0x1000
        self.assertTrue(0<=off<=len(raw) and off+size<=len(raw))
        return raw[off:off+size]

    def test_original_words_establish_both_paths(self):
        self.assertEqual(check_joined(self.g,self.audit,self.read),1)
        self.assertEqual(query(self.g,0x1014)[0]['last_suspensions'],[None,0x1010])
        self.assertIn('no additional await, 0x1010',render(query(self.g)))

    def test_actual_overwrite_kills_join(self):
        self.words[3]=0xf81f03a1
        with self.assertRaises(AssertionError):check_joined(self.g,self.audit,self.read)

    def test_actual_branch_requires_two_histories(self):
        self.words[2]=0xb4000041
        with self.assertRaises(AssertionError):check_joined(self.g,self.audit,self.read)

    def test_map_on_one_path_is_required(self):
        self.g['saved_reference_stack_maps'][0]['objects']=[]
        self.audit['saved_reference_stack_maps'][0]['objects']=[]
        with self.assertRaises(AssertionError):check_joined(self.g,self.audit,self.read)

    def test_typed_map_identity_is_required(self):
        self.audit['saved_reference_stack_maps'][0]['spill_slots']-=1
        with self.assertRaises(AssertionError):check_joined(self.g,self.audit,self.read)

    def test_alternate_reload_entry_is_refused(self):
        self.g['receiver_metadata']['entries'].append(0x1014)
        with self.assertRaises(AssertionError):check_joined(self.g,self.audit,self.read)

    def test_history_is_not_a_nearby_call_guess(self):
        self.o['last_suspensions']=[None,0x100c]
        with self.assertRaises(AssertionError):check_joined(self.g,self.audit,self.read)

    def test_invalid_history_sets_refused(self):
        for last in ([],[None],[None,None],[0,0x1010],[0x1010,None],[None,0x1010,0x1010]):
            self.o['last_suspensions']=last
            with self.subTest(last=last),self.assertRaises(AssertionError):validate_structure(self.g)

    def test_scope_and_delivery_parent_are_mandatory(self):
        for k,v in [('scope','unconditional'),('class_id',9),('status','step_limit'),('source_await',0x1008)]:
            g=copy.deepcopy(self.g);g['joined_reference_contexts'][0][k]=v
            with self.subTest(key=k),self.assertRaises((AssertionError,KeyError)):validate_structure(g)
        self.g['await_future_bindings'][0]['conditions']=[]
        with self.assertRaises(AssertionError):validate_structure(self.g)

    def test_original_certificate_is_not_duplicated(self):
        self.g['saved_reference_contexts'][0]['observations']=[dict(site=0x1014)]
        with self.assertRaises(AssertionError):validate_structure(self.g)

    def test_comment_attachment_and_claim_scope(self):
        text='// '+note(self.c,self.o)+'\n// 0x1014: ldur x2, [fp, #-16]\n'
        self.assertEqual(sum(check_stream(self.g,io.StringIO(text)).values()),1)
        for bad in [text+text,text.replace('reference only','field contents known'),text.replace('0x1014:','0x1018:')]:
            with self.assertRaises(AssertionError):check_stream(self.g,io.StringIO(bad))

    def test_full_compact_gzip_query_agreement(self):
        with tempfile.TemporaryDirectory() as name:
            p=Path(name);plain=p/'snapshot_calls.json';z=plain.with_suffix('.json.gz')
            rows=query(self.g)
            for detail in ('full','compact'):
                g=dict(self.g,export=dict(detail=detail,omitted=[] if detail=='full' else ['receiver_blocks','call_effect_states']))
                raw=json.dumps(g).encode();plain.write_bytes(raw);z.write_bytes(gzip.compress(raw))
                self.assertEqual(query(load_graph(p)),rows);plain.unlink();self.assertEqual(query(load_graph(p)),rows)

    def test_old_schema_remains_readable_by_existing_checkers(self):
        self.g['format']=45
        self.assertEqual(check_joined(self.g,{},lambda *_:self.fail('Unexpected old-format byte read')),0)
        with self.assertRaisesRegex(ValueError,'format 46'):query(self.g)


if __name__ == '__main__':unittest.main()
