"""Independent instruction checks for generated descriptor-vector prologues."""

def verify(row, abi, read):
    if row.get('parameter', False):
        return verify_parameters(row, abi, read)
    import capstone as cs
    from capstone import arm64 as a
    assert abi['supported'] and abi['field_bytes'] == 4 and abi['smi_shift'] == 1 and abi['frame_argument_base'] == 16
    target, branch = row['target'], row['branch']
    assert target % 4 == 0 and target+8 <= row['type_arguments_load'] < branch == row['type_arguments_load']+4
    assert branch < row['size_load'] <= branch+32 and row['address_add'] == row['size_load']+4 and row['vector_load'] == row['size_load']+8
    prefix = list(range(target, branch+4, 4))
    assert len(prefix) <= 65 and row['proof'] == prefix+[row['size_load'], row['address_add'], row['vector_load']]
    md = cs.Cs(cs.CS_ARCH_ARM64, cs.CS_MODE_LITTLE_ENDIAN); md.detail = True
    decoded = list(md.disasm(read(target, row['vector_load']+4-target), target))
    ins = {i.address:i for i in decoded}
    assert all(p in ins for p in row['proof']), 'Undecodable descriptor-use proof'
    first, frame = ins[target], ins[target+4]
    assert first.id == a.ARM64_INS_STP and first.writeback and len(first.operands)==3
    assert [o.reg for o in first.operands[:2]] == [a.ARM64_REG_FP,a.ARM64_REG_LR]
    assert first.operands[2].mem.base == a.ARM64_REG_X15 and first.operands[2].mem.disp == -16
    assert frame.id == a.ARM64_INS_MOV and [o.reg for o in frame.operands] == [a.ARM64_REG_FP,a.ARM64_REG_X15]
    def number(r):
        name=md.reg_name(r)
        if name in ('fp','lr'):return 29 if name=='fp' else 30
        return int(name[1:]) if name and name[0] in ('x','w') and name[1:].isdigit() else -1
    def full(r):return md.reg_name(r).startswith('x') or r in (a.ARM64_REG_FP,a.ARM64_REG_LR)
    def memory(i):
        assert i.id in (a.ARM64_INS_LDR,a.ARM64_INS_LDUR) and not i.writeback and len(i.operands)==2
        assert i.operands[1].type==a.ARM64_OP_MEM and not i.operands[1].mem.index
        return i.operands[0].reg,i.operands[1].mem.base,i.operands[1].mem.disp
    aliases={abi['descriptor_register']};stack=-16
    for pc in prefix[2:-2]:
        i=ins[pc];o=i.operands
        assert not any(i.group(g) for g in (cs.CS_GRP_CALL,cs.CS_GRP_JUMP,cs.CS_GRP_RET,cs.CS_GRP_INT))
        if i.id==a.ARM64_INS_MOV and len(o)==2 and all(v.type==a.ARM64_OP_REG and full(v.reg) for v in o):
            dst,src=map(lambda v:number(v.reg),o);assert 0<=dst<29 and dst!=15
            alias=src in aliases;aliases.discard(dst)
            if alias:aliases.add(dst)
        elif i.id==a.ARM64_INS_SUB and len(o)==3 and o[0].reg==o[1].reg==a.ARM64_REG_X15 and o[2].type==a.ARM64_OP_IMM:
            assert not i.update_flags and not i.writeback and 0<=o[2].imm<=1048576 and not o[2].shift.value
            stack-=o[2].imm;assert stack>=-1048576
        elif i.id in (a.ARM64_INS_STR,a.ARM64_INS_STUR) and not i.writeback and len(o)==2 and o[1].type==a.ARM64_OP_MEM:
            m=o[1].mem;assert not m.index and m.base in (a.ARM64_REG_FP,a.ARM64_REG_X15)
            offset=m.disp+(-16 if m.base==a.ARM64_REG_FP else stack)
            assert stack<=offset and offset+(8 if full(o[0].reg) else 4)<=-16
        elif i.id in (a.ARM64_INS_NOP,a.ARM64_INS_CMP,a.ARM64_INS_TST):pass
        else:
            # The native prefix lowerer accepts only plain single-destination
            # operations. Inspect original operand effects independently here.
            assert i.id in (a.ARM64_INS_LDR,a.ARM64_INS_LDUR,a.ARM64_INS_ADD,a.ARM64_INS_SUB,a.ARM64_INS_MOVZ,a.ARM64_INS_MOVN,a.ARM64_INS_MOVK,a.ARM64_INS_UBFX,a.ARM64_INS_SBFX,a.ARM64_INS_SBFIZ)
            assert not i.writeback and not i.update_flags and o and o[0].type==a.ARM64_OP_REG
            dst=number(o[0].reg);assert 0<=dst<29 and dst!=15;aliases.discard(dst)
    length=ins[row['type_arguments_load']];reg,base,offset=memory(length)
    assert not full(reg) and 0<=number(reg)<15 and number(base) in aliases and offset==abi['type_arguments_offset']
    b=ins[branch];assert b.id==a.ARM64_INS_CBNZ and b.operands[0].reg==reg and b.operands[1].imm==row['size_load']
    aliases.discard(number(reg))
    size=ins[row['size_load']];size_reg,base,offset=memory(size)
    assert not full(size_reg) and 0<=number(size_reg)<15 and number(base) in aliases and offset==abi['size_offset']
    add=ins[row['address_add']];o=add.operands
    assert add.id==a.ARM64_INS_ADD and len(o)==3 and not add.writeback and not add.update_flags
    assert full(o[0].reg) and 0<=number(o[0].reg)<15 and o[1].reg==a.ARM64_REG_FP
    assert o[2].reg==size_reg and o[2].ext==a.ARM64_EXT_SXTW and o[2].shift.value==2
    _,base,offset=memory(ins[row['vector_load']]);assert base==o[0].reg and offset==abi['frame_argument_base']
    assert full(ins[row['vector_load']].operands[0].reg)
    return True


def verify_parameters(row, abi, read):
    import capstone as cs
    from capstone import arm64 as a
    assert abi['supported'] and abi.get('count_offset', 0) > 0 and abi['frame_argument_base'] == 16
    assert row['type_arguments_load'] == row['branch'] == 0 and row['vector_load'] == row['address_add']+4
    assert row['proof'] == list(range(row['target'], row['vector_load']+4, 4)) and 5 <= len(row['proof']) <= 65
    md=cs.Cs(cs.CS_ARCH_ARM64, cs.CS_MODE_LITTLE_ENDIAN);md.detail=True
    ins=list(md.disasm(read(row['target'], row['vector_load']+4-row['target']),row['target']))
    assert len(ins)==len(row['proof'])
    def num(reg):
        name=md.reg_name(reg)
        return 29 if name=='fp' else 30 if name=='lr' else int(name[1:]) if name and name[0] in 'xw' and name[1:].isdigit() else -1
    def full(reg):return md.reg_name(reg).startswith('x') or reg in (a.ARM64_REG_FP,a.ARM64_REG_LR)
    o=ins[0].operands
    assert ins[0].id==a.ARM64_INS_STP and ins[0].writeback and len(o)==3
    assert o[0].reg==a.ARM64_REG_FP and o[1].reg==a.ARM64_REG_LR and o[2].mem.base==a.ARM64_REG_X15 and o[2].mem.disp==-16
    assert ins[1].id==a.ARM64_INS_MOV and [o.reg for o in ins[1].operands]==[a.ARM64_REG_FP,a.ARM64_REG_X15]
    aliases={abi['descriptor_register']};counts={};stack=-16
    for i in ins[2:-2]:
        o=i.operands
        assert not any(i.group(g) for g in (cs.CS_GRP_CALL,cs.CS_GRP_JUMP,cs.CS_GRP_RET,cs.CS_GRP_INT))
        if i.id in (a.ARM64_INS_LDR,a.ARM64_INS_LDUR) and len(o)==2 and o[1].type==a.ARM64_OP_MEM and not i.writeback and not o[1].mem.index and num(o[1].mem.base) in aliases and o[1].mem.disp==abi['count_offset'] and not full(o[0].reg):
            dst=num(o[0].reg);assert 0<=dst<15;aliases.discard(dst);counts[dst]=(0,i.address)
        elif i.id==a.ARM64_INS_MOV and len(o)==2 and all(v.type==a.ARM64_OP_REG and full(v.reg) for v in o):
            dst,src=map(lambda v:num(v.reg),o);assert 0<=dst<29 and dst!=15
            alias=src in aliases;aliases.discard(dst)
            if alias:aliases.add(dst)
            value=counts.get(src);counts.pop(dst,None)
            if value is not None:counts[dst]=value
        elif i.id==a.ARM64_INS_SUB and len(o)==3 and o[0].reg==o[1].reg==a.ARM64_REG_X15:
            assert o[2].type==a.ARM64_OP_IMM and 0<=o[2].imm<=1048576 and not o[2].shift.value and not i.writeback and not i.update_flags
            stack-=o[2].imm;assert stack>=-1048576
        elif i.id==a.ARM64_INS_SUB and len(o)==3 and o[2].type==a.ARM64_OP_IMM and num(o[1].reg) in counts and full(o[0].reg) and full(o[1].reg):
            assert 0<=o[2].imm<=64 and o[2].imm%2==0 and not o[2].shift.value and not i.writeback and not i.update_flags
            dst=num(o[0].reg);bias,pc=counts[num(o[1].reg)];assert 0<=dst<15 and bias-o[2].imm>=-64
            aliases.discard(dst);counts[dst]=(bias-o[2].imm,pc)
        elif i.id in (a.ARM64_INS_STR,a.ARM64_INS_STUR) and len(o)==2 and not i.writeback:
            m=o[1].mem;assert not m.index and m.base in (a.ARM64_REG_FP,a.ARM64_REG_X15)
            offset=m.disp+(-16 if m.base==a.ARM64_REG_FP else stack)
            assert stack<=offset and offset+(8 if full(o[0].reg) else 4)<=-16
        elif i.id in (a.ARM64_INS_CMP,a.ARM64_INS_TST,a.ARM64_INS_NOP):pass
        else:
            assert i.id in (a.ARM64_INS_LDR,a.ARM64_INS_LDUR,a.ARM64_INS_ADD,a.ARM64_INS_SUB,a.ARM64_INS_MOVZ,a.ARM64_INS_MOVN,a.ARM64_INS_MOVK,a.ARM64_INS_UBFX,a.ARM64_INS_SBFX,a.ARM64_INS_SBFIZ)
            assert not i.writeback and not i.update_flags and o and o[0].type==a.ARM64_OP_REG
            dst=num(o[0].reg);assert 0<=dst<29 and dst!=15;aliases.discard(dst);counts.pop(dst,None)
    i=ins[-2];o=i.operands
    assert i.address==row['address_add'] and i.id==a.ARM64_INS_ADD and len(o)==3 and not i.writeback and not i.update_flags
    assert full(o[0].reg) and 0<=num(o[0].reg)<15 and o[1].reg==a.ARM64_REG_FP
    assert not full(o[2].reg) and o[2].ext==a.ARM64_EXT_SXTW and o[2].shift.value==2
    assert counts[num(o[2].reg)]==(row['count_bias'],row['size_load'])
    load=ins[-1];v=load.operands
    assert load.id in (a.ARM64_INS_LDR,a.ARM64_INS_LDUR) and not load.writeback and len(v)==2 and full(v[0].reg)
    assert not v[1].mem.index and v[1].mem.base==o[0].reg and v[1].mem.disp==row['frame_load_offset']
    return True
