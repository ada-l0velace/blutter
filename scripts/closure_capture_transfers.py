"""Replay matched closure captures and local copies using original ARM64 words."""
from collections import Counter
import bisect
import json
import struct
from field_branch_uses import signed, check_stream as check_comments
from async_field_accesses import expected_layout

FIELDS = ('closure_capture_layout','closure_capture_transfers','closure_capture_work')


def known_entries(graph,read):
    entries=set(graph['receiver_metadata']['entries']) | {
        e['target'] for e in graph['edges'] if e['target'] is not None}
    entries.update(graph.get('dispatch_table',{}).get('entries',[]))
    for node in graph['nodes']:
        if not node['decoded']:
            continue
        for n,(word,) in enumerate(struct.iter_unpack('<I',read(node['start'],node['end']-node['start']))):
            shift,bits=(0,26) if word&0x7c000000==0x14000000 else ((5,19) if word&0xff000010==0x54000000 or word&0x7e000000==0x34000000 else ((5,14) if word&0x7e000000==0x36000000 else (0,0)))
            if bits:
                entries.add(node['start']+n*4+4*signed((word>>shift)&((1<<bits)-1),bits))
    return entries


def memory(word, width, store=False):
    unsigned = (0xb9000000 if store else 0xb9400000) if width == 4 else (0xf9000000 if store else 0xf9400000)
    unscaled = (0xb8000000 if store else 0xb8400000) if width == 4 else (0xf8000000 if store else 0xf8400000)
    if (word & 0xffc00000) == unsigned:
        displacement = ((word >> 10) & 0xfff)*width
    elif (word & 0xffe00c00) in ((unscaled,) if store else (unscaled,unscaled|0x800)):
        displacement = signed((word >> 12)&0x1ff,9)
    else:
        return None
    return word & 31, (word >> 5) & 31, displacement


def derive(graph, audit, read, origin_index, pool, model, kind, prepared=None):
    entry = model['entry']
    nodes = graph['nodes']
    starts = prepared['starts'] if prepared else [n['start'] for n in nodes]
    index = bisect.bisect_right(starts,entry)-1
    if index < 0 or not entry < nodes[index]['end']:
        return None, 0
    node = nodes[index]
    length = min(64,node['end']-entry)
    code = read(entry,length)
    if len(code)<48:
        return None,length
    words = struct.unpack_from('<12I',code)
    entries = prepared['entries'] if prepared else known_entries(graph,read)
    if any(entry+4*n in entries for n in range(1,12)):
        return None,length
    body = prepared['bodies'].get(node['start']) if prepared else next((b for b in audit['completion_bodies'] if b['payload']==node['start']),None)
    discarded = prepared['discarded'] if prepared else {e['entry'] for table in audit.get('tables',[]) for e in table['entries'] if e['index']<table['first_with_code']}
    handler_basis = 'retained_table' if body and body['available'] else 'discarded_code'
    if (not body or not body['available']) and node['start'] not in discarded:
        return None,length
    if body and any(entry<h<=entry+44 for h in body['handlers']):
        return None,length
    if words[:2]!=(0xa9bf79fd,0xaa0f03fd) or (words[2]&0xffc003ff)!=0xd10001ef:
        return None,length
    stack = (words[2] >> 10)&0xfff
    if stack<8 or stack%8:
        return None,length
    closure = memory(words[3],8)
    if not closure or closure[0]>=15 or closure[1] not in (15,29):
        return None,length
    closure_reg,base,disp = closure
    coordinate = -16 if base == 29 else -16-stack
    if coordinate+disp!=model['entry_sp_offset']:
        return None,length
    layout = graph['closure_capture_layout']
    context_offset = dict(layout['context_offsets'])[kind]
    capture = memory(words[4],4)
    if not capture or capture[0]>=15 or capture[1:]!=(closure_reg,context_offset):
        return None,length
    context = capture[0]
    if words[5]!=(0x8b1c8000 | (context<<5) | context):
        return None,length
    value = memory(words[6],4)
    if not value or value[0]>=15 or value[1]!=context or not 0<=value[2]<=4096:
        return None,length
    value_reg = value[0]
    if words[7]!=(0x8b1c8000 | (value_reg<<5) | value_reg):
        return None,length
    save = memory(words[8],8,store=True)
    if not save or save[:2]!=(value_reg,29) or not -stack<=save[2]<=layout['first_local_offset'] or save[2]%8:
        return None,length
    # Native scope uses a plain unscaled frame store.
    if (words[8]&0xffe00c00)!=0xf8000000 or (words[9]&0xfc000000)!=0x94000000:
        return None,length
    target = entry+36+4*signed(words[9]&0x3ffffff,26)
    allocations = dict(graph['receiver_metadata']['allocation_returns'])
    if target not in allocations:
        return None,length
    cid = allocations[target]
    reload = memory(words[10],8)
    if not reload or not 0<reload[0]<15 or reload[1:]!=(29,save[2]):
        return None,length
    destination = memory(words[11],4,store=True)
    dest_layout = expected_layout(cid,audit)
    if not destination or destination[:2]!=(reload[0],0) or dest_layout['kind']!='instance':
        return None,length
    offset = destination[2]+dest_layout['tag']
    if (destination[2]<0 or offset%4 or not dest_layout['header']<=offset<=dest_layout['end']-4
            or offset in dest_layout['excluded'] or offset in dest_layout['unboxed']):
        return None,length
    maps = prepared['maps'] if prepared else {(m['payload'],m['site']):m for m in audit['closure_capture_stack_maps']}
    stack_map = maps.get((node['start'],entry+36))
    if not stack_map or not stack_map['available']:
        return None,length
    gap = stack_map['register_slots']==0 and save[2]<=layout['first_local_offset']-stack_map['spill_slots']*8
    if save[2] not in stack_map['objects'] and not gap:
        return None,length
    return dict(origin=origin_index,call=graph['call_input_origins'][origin_index]['site'],
        pool_index=pool,entry=entry,fixed=model['fixed'],entry_sp_offset=model['entry_sp_offset'],
        context_displacement=context_offset,value_displacement=value[2],saved_slot=save[2],
        value_read=entry+24,allocation=entry+36,target=target,reload=entry+40,store=entry+44,
        class_id=cid,destination_offset=offset,stack_map=stack_map,layout=dest_layout,handler_basis=handler_basis),length


def check_transfers(graph,audit,read):
    if graph.get('format',0)<50:
        return 0
    assert graph['closure_capture_layout']==audit['closure_capture_layout']
    layout=graph['closure_capture_layout']
    work=graph['closure_capture_work']
    assert 0<=work['steps']<=200000 and work['steps']+work['remaining']==200000
    assert 0<=work['bytes']<=524288 and 0<=work['candidates']<=4096 and type(work['complete']) is bool
    expected=[];candidates=byte_count=0
    prepared=dict(starts=[n['start'] for n in graph['nodes']],
        entries=known_entries(graph,read),
        bodies={b['payload']:b for b in audit.get('completion_bodies',[])},
        maps={(m['payload'],m['site']):m for m in audit['closure_capture_stack_maps']},
        discarded={e['entry'] for table in audit.get('tables',[]) for e in table['entries'] if e['index']<table['first_with_code']})

    if layout['slot_bytes']==4 and layout['tag']==1 and -4096<=layout['first_local_offset']<=-8 and graph['receiver_metadata']['heap_bits_register']=='x28':
        contracts={s['entry']:s for s in graph['stub_input_contracts']}
        edges={e['site']:e for e in graph['edges']}
        models={m['pool_index']:m for m in audit['closure_entry_models']}
        objects={o['pool_index']:o for o in graph['input_object_catalog']}
        for oi,origin in enumerate(graph['call_input_origins']):
            if origin['role']!='closure_function':
                continue
            contract=contracts.get(edges[origin['site']]['target'])
            if not contract or contract['kind'] not in dict(layout['context_offsets']):
                continue
            for step in origin['chain']:
                pool=step['pool_index']
                if pool not in models or pool not in objects or objects[pool]['kind']!='function' or step['stop']!='load_endpoint':
                    continue
                model=models[pool]
                assert 1<=model['fixed']<=32 and model['entry_sp_offset']==(model['fixed']-1)*8
                assert objects[pool]['entry']==model['entry']
                candidates+=1
                result,size=derive(graph,audit,read,oi,pool,model,contract['kind'],prepared)
                byte_count+=size
                if result:expected.append(result)
                break
    if work['complete']:
        assert work['candidates']==candidates and work['bytes']==byte_count
        assert graph['closure_capture_transfers']==expected, 'Closure capture differs from original words and typed metadata'
    else:
        assert all(t in expected for t in graph['closure_capture_transfers'])
    return len(graph['closure_capture_transfers'])


def capture_note(t):
    return (f"closure capture: entry SP{t['entry_sp_offset']:+d} -> capture load {t['entry']+16:#x} "
            f"-> load {t['value_read']:#x} at {t['value_displacement']:+#x}; saved to FP{t['saved_slot']:+d}; "
            f"initializes class {t['class_id']:#x} instance slot {t['destination_offset']:#x} "
            f"[at callback invocation; tagged local across allocator {t['target']:#x}; normal allocation return]")


def callback_note(t):
    return (f"closure capture callback: entry {t['entry']:#x}; capture read {t['value_read']:#x} "
            f"reaches class {t['class_id']:#x} instance slot {t['destination_offset']:#x} at {t['store']:#x} "
            "[matched closure entry and capture layout; contents at invocation]")


def expected_notes(graph):
    captures={(t['store'],capture_note(t)) for t in graph['closure_capture_transfers']}
    callbacks=[(t['call'],callback_note(t)) for t in graph['closure_capture_transfers']]
    return Counter(list(captures)+callbacks)


def check_stream(stream,expected):
    return check_comments(stream,expected,prefix='closure capture')


def check_output(graph,output):
    from native_assembly import native_assembly_streams
    expected=expected_notes(graph);seen=Counter()
    manifest=json.loads((output/'snapshot_code.json').read_text())
    for _,stream in native_assembly_streams(output,manifest):
        seen.update(check_stream(stream,expected))
    assert seen==expected,'Missing or duplicate closure capture comments'
    return sum(seen.values())
