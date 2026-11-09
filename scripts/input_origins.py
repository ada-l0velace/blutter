"""Inspect and independently replay bounded physical input provenance proofs."""
import json
import struct


def render_origins(rows, objects):
    catalogue={o['pool_index']:o for o in objects}
    lines=[]
    for row in rows:
        label=f"supplied input[{row['index']}]" if row['index'] is not None else row['role']
        if row['register'] is not None:label+=f" (X{row['register']})"
        lines.append('  Origin of '+label+' [normal fallthrough]:')
        for step in row['chain']:
            v=step['source'];prefix='    '+step['relation']+': '
            if v is None:lines.append(prefix+'unproved ('+step['stop']+')');continue
            obj=catalogue.get(step['pool_index'])
            if obj:
                detail=obj['kind']+' '+json.dumps(obj['text'],ensure_ascii=True)
                if obj['entry'] is not None:detail+=f"; entry {obj['entry']:#x}"
            elif step['pool_index'] is not None:detail=f"pool[{step['pool_index']}]"
            elif v['load']:detail=f"{v['kind']} [X{v['load']['base']}{v['load']['displacement']:+}] (contents unproved)"
            elif v['kind']=='entry_register':detail=f"entry X{v['bits']}"
            elif v['bits'] is not None:detail=f"raw word {v['bits']:#x}"
            else:detail=v['kind']+(f"; callee {v['callee']:#x}" if v['callee'] is not None else '')
            lines.append(prefix+detail+f" @{v['site']:#x}")
    return lines


def check_origins(graph, audit, read):
    if graph.get('format',0)<36:return 0
    import capstone as cs
    from check_snapshot_annotations import constant_move
    from capstone import arm64 as a
    md=cs.Cs(cs.CS_ARCH_ARM64,cs.CS_MODE_LITTLE_ENDIAN);md.detail=True
    edges={e['site']:e for e in graph['edges']};nodes={n['start']:n for n in graph['nodes']}
    shapes={s['site']:s for s in graph['call_input_shapes']}
    contracts={s['entry']:s for s in graph['stub_input_contracts']}
    asyncs={s['site']:s for s in graph['async_boundaries']}
    references={r['site']:r for r in graph['references'] if r['kind']=='pool' and r['access']=='load' and r['width']==8}
    entries={v['address'] for n in graph['nodes'] for v in n.get('names', [])}
    entries.update(e['target'] for e in graph['edges'] if e.get('target') is not None)
    entries.update(graph.get('dispatch_table', {}).get('entries', []))
    for node in graph['nodes']:
        if not node['decoded']:continue
        for n,(word,) in enumerate(struct.iter_unpack('<I',read(node['start'],node['end']-node['start']))):
            shift,bits=(0,26) if word&0x7c000000==0x14000000 else ((5,19) if word&0xff000010==0x54000000 or word&0x7e000000==0x34000000 else ((5,14) if word&0x7e000000==0x36000000 else (0,0)))
            if bits:
                delta=(word>>shift)&((1<<bits)-1)
                if delta&(1<<(bits-1)):delta-=1<<bits
                entries.add(node['start']+n*4+delta*4)
    objects={o['pool_index']:o for o in graph['input_object_catalog']}
    assert len(objects)==len(graph['input_object_catalog'])
    if objects:
        assert audit is not None,'Input objects need a typed SDK audit'
        typed={o['pool_index']:o for o in audit['input_object_catalog']}
        assert all(o==typed.get(index) for index,o in objects.items()),'Input object metadata mismatch'
    def number(reg):
        name=md.reg_name(reg)
        return 29 if name=='fp' else 30 if name=='lr' else int(name[1:]) if name and name[0] in 'xw' and name[1:].isdigit() else -1
    def width(reg):
        name=md.reg_name(reg)
        return 8 if name and name[0] in 'xd' or reg in (a.ARM64_REG_FP,a.ARM64_REG_LR) else 4 if name and name[0] in 'ws' else 0
    def replay(value, consumer, location):
        proof=value['proof'];start=value['site'];kind=value['kind']
        assert proof==list(range(start,consumer+4,4)) and 1<=len(proof)<=65,'Malformed input provenance span'
        assert not any(p in entries for p in proof[1:]),'Known entry bypasses input provenance'
        instructions=list(md.disasm(read(start,consumer+4-start),start));assert len(instructions)==len(proof)
        reg,memory=location;compressed=False
        for i in reversed(instructions[:-1]):
            o=i.operands;first=i.address==start
            if first and kind=='entry_register':
                # This source precedes the first payload instruction; replay it
                # too, then test the unresolved entry register below.
                pass
            assert not ((i.group(cs.CS_GRP_JUMP) and not i.group(cs.CS_GRP_CALL)) or i.group(cs.CS_GRP_RET) or i.group(cs.CS_GRP_INT)),'Origin crosses control transfer'
            if i.group(cs.CS_GRP_CALL):
                assert first and memory is None and reg==0 and not compressed
                assert kind in ('post_call_x0','await_delivery') and i.id in (a.ARM64_INS_BL,a.ARM64_INS_BLR)
                assert value['callee']==(o[0].imm if i.id==a.ARM64_INS_BL else None)
                if kind=='await_delivery':assert asyncs[i.address]['operation'] in ('await','await_with_type_check')
                return
            if memory and memory[0]==15 and i.id in (a.ARM64_INS_ADD,a.ARM64_INS_SUB) and len(o)==3 and o[0].type==o[1].type==a.ARM64_OP_REG and o[0].reg==o[1].reg==a.ARM64_REG_X15 and o[2].type==a.ARM64_OP_IMM and not o[2].shift.value:
                memory=(15,memory[1]+o[2].imm*(1 if i.id==a.ARM64_INS_ADD else -1));continue
            if i.id in (a.ARM64_INS_STR,a.ARM64_INS_STUR,a.ARM64_INS_STP,a.ARM64_INS_STRB,a.ARM64_INS_STURB,a.ARM64_INS_STRH,a.ARM64_INS_STURH):
                assert o[-1].type==a.ARM64_OP_MEM and not o[-1].mem.index
                if i.writeback:
                    assert i.id in (a.ARM64_INS_STR,a.ARM64_INS_STP) and len(o)==(3 if i.id==a.ARM64_INS_STP else 2) and o[-1].mem.base==a.ARM64_REG_X15 and -256<=o[-1].mem.disp<0 and o[-1].mem.disp%8==0
                if memory is None:continue
                base,off=memory;m=o[-1].mem;assert number(m.base)==base,'Possible alias in input proof'
                stores=o[:-1]
                for part,v in enumerate(stores):
                    size=1 if i.id in (a.ARM64_INS_STRB,a.ARM64_INS_STURB) else 2 if i.id in (a.ARM64_INS_STRH,a.ARM64_INS_STURH) else width(v.reg)
                    disp=(0 if i.writeback else m.disp)+part*size
                    if disp>=off+8 or disp+size<=off:continue
                    assert disp==off and size==8
                    if v.reg==a.ARM64_REG_XZR:
                        assert first and kind=='literal' and value['bits']==0;return
                    reg=number(v.reg);assert 0<=reg<31;memory=None;break
                if i.writeback and memory:memory=(memory[0],memory[1]+m.disp)
                continue
            if i.id in (a.ARM64_INS_NOP,a.ARM64_INS_CMP,a.ARM64_INS_CMN,a.ARM64_INS_TST):continue
            if memory is None and i.id==a.ARM64_INS_ADD and len(o)==3 and all(v.type==a.ARM64_OP_REG for v in o) and number(o[0].reg)==reg and o[0].reg==o[1].reg and o[2].reg==a.ARM64_REG_X28 and o[2].shift.type==a.ARM64_SFT_LSL and o[2].shift.value==32:
                assert graph['receiver_metadata']['heap_bits_register']=='x28';compressed=True;continue
            assert not i.writeback and not i.update_flags
            assert i.id in (a.ARM64_INS_MOV,a.ARM64_INS_MOVZ,a.ARM64_INS_MOVN,a.ARM64_INS_MOVK,a.ARM64_INS_LDR,a.ARM64_INS_LDUR,a.ARM64_INS_ADD,a.ARM64_INS_SUB,a.ARM64_INS_UBFX,a.ARM64_INS_SBFX,a.ARM64_INS_SBFIZ),'Unsupported provenance instruction'
            assert o and o[0].type==a.ARM64_OP_REG
            destination=number(o[0].reg)
            if memory:
                assert destination!=memory[0];continue
            if destination!=reg:continue
            assert width(o[0].reg)==8 or compressed and width(o[0].reg)==4
            if i.id in (a.ARM64_INS_MOV,a.ARM64_INS_MOVZ,a.ARM64_INS_MOVN):
                move=constant_move(int.from_bytes(i.bytes,'little'))
                if move and (move[0]=='literal' or move[0]=='copy' and move[3]==31):
                    assert first and kind=='literal' and not compressed and move[1]==reg and move[2]==64
                    assert value['bits']==(move[3] if move[0]=='literal' else 0);return
            if i.id==a.ARM64_INS_MOV and len(o)==2 and o[1].type==a.ARM64_OP_REG:
                assert not compressed and width(o[1].reg)==8;reg=number(o[1].reg);continue
            if i.id in (a.ARM64_INS_LDR,a.ARM64_INS_LDUR):
                assert len(o)==2 and o[1].type==a.ARM64_OP_MEM and not o[1].mem.index
                expected=dict(base=number(o[1].mem.base),displacement=o[1].mem.disp,bytes=width(o[0].reg))
                if first:
                    assert kind in ('load','load_compressed') and value['load']==expected and compressed==(kind=='load_compressed');return
                assert not compressed and expected['base']==29 and expected['bytes']==8
                memory=(29,expected['displacement']);continue
            raise AssertionError('Unexpected definition in input proof')
        assert kind=='entry_register' and memory is None and reg==value['bits'] and 0<=reg<15 and not compressed
    total=0;seen=set();used_objects=set()
    for row in graph['call_input_origins']:
        key=(row['site'],row['role'],row['index'],row['register']);assert key not in seen;seen.add(key)
        edge=edges[row['site']];node=nodes[row['payload']]
        assert edge['source']==row['payload'] and row['condition']=='normal_fallthrough' and 1<=len(row['chain'])<=3
        if row['index'] is not None:
            s=shapes[row['site']];assert row['role']=='supplied_input' and 0<=row['index']<s['count'] and row['register'] is None
            assert row['sp_offset']==(s['count']-1-row['index'])*8;location=(0,(15,row['sp_offset']))
        else:
            assert row['sp_offset'] is None and type(row['register']) is int and 0<=row['register']<15
            if row['role'] in ('await_input','completion_operand'):assert row['site'] in asyncs and row['register']==0
            else:assert any(v['role']==row['role'] and v['register']=='x'+str(row['register']) for v in contracts[edge['target']]['inputs'])
            location=(row['register'],None)
        consumer=row['site'];previous=None
        for depth,step in enumerate(row['chain']):
            total+=step['steps'];assert type(step['steps']) is int and 0<=step['steps']<=64
            if depth==0:assert step['relation']=='input'
            elif step['relation']=='load_base':
                assert previous and previous['load'] and previous['load']['base']<15
                consumer=previous['site'];location=(previous['load']['base'],None)
            else:
                assert step['relation']=='closure_function' and previous and previous['kind']=='post_call_x0'
                contract=contracts[previous['callee']]
                roles=[v for v in contract['inputs'] if v['role']=='closure_function'];assert len(roles)==1
                consumer=previous['site'];location=(int(roles[0]['register'][1:]),None)
            value=step['source']
            if value:
                assert node['start']<=value['site']<=consumer<node['end']
                replay(value,consumer,location)
                if value['kind']=='entry_register':assert value['site']==node['start']
            else:assert depth==len(row['chain'])-1
            if step['pool_index'] is not None:
                assert value and value['kind']=='load' and references[value['site']]['pool_index']==step['pool_index']
                if step['pool_index'] in objects:used_objects.add(step['pool_index'])
            previous=value
    assert used_objects==set(objects),'Unused input object catalogue entries'
    work=graph['input_origin_work'];assert work['limit']==2000000 and work['steps']==total and work['steps']+work['remaining']==work['limit']
    return len(seen)
