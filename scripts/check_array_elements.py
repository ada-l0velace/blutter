"""Independent block-local array-content transfers over decoded original words."""
import capstone as cs
from capstone import arm64 as a

# Existing receiver-certificate fact kinds, independent of SDK class IDs.
WORD, OBJECT, STACK = 1, 3, 8


class ArrayTrace:
    def __init__(self, metadata, fresh, all_writes, number, width, read_reg, entry_input=None):
        self.contract = metadata.get('array_body_contract', [])
        self.result_reg = int(metadata['allocation_result_register'][1:])
        self.heap_fixed = metadata.get('heap_bits_register') == 'x28' and 28 not in all_writes
        self.number, self.width, self.read_reg = number, width, read_reg
        self.seed = fresh
        self.aliases = {self.result_reg: 0} if fresh is not None else {}
        self.packed, self.cells, self.roots, self.words = {}, {}, set(), {}
        self.packed_indices = {}
        self.input_binding = entry_input is not None
        self.input_offset = entry_input['sp_offset'] if entry_input is not None else None
        if entry_input is not None:
            self.seed = (0, entry_input['length'])
            self.aliases.clear()
            self.roots.add(entry_input['sp_offset'])
            self.cells = {self.contract[2]+i*self.contract[3]: cid for i, cid in entry_input['elements']}

    def clear(self):
        self.seed = None
        self.aliases.clear()
        self.packed.clear()
        self.cells.clear()
        self.roots.clear()
        self.words.clear()
        self.packed_indices.clear()
        self.input_binding = False
        self.input_offset = None

    def continue_length_call(self, writes):
        # The verified leaf has no writes/allocating calls. Keep only the
        # limited array facts represented by the producer's one-edge handoff.
        self.aliases = {r: value for r, value in self.aliases.items() if not writes & (1 << r)}
        self.packed.clear()
        self.packed_indices.clear()
        self.words.clear()

    def address(self, ins, memory):
        base = self.aliases.get(self.number(ins, memory.mem.base))
        if base is not None and not ins.writeback and not memory.mem.index:
            at = base + memory.mem.disp
            if -(1 << 63) <= at < 1 << 63:
                return at
        return None

    def load(self, ins):
        ops = ins.operands
        if self.seed is not None and ins.id in (a.ARM64_INS_LDR, a.ARM64_INS_LDUR) and len(ops) == 2 and ops[0].type == a.ARM64_OP_REG and ops[1].type == a.ARM64_OP_MEM and self.width(ins, ops[0].reg) // 8 == self.contract[3]:
            return self.cells.get(self.address(ins, ops[1]))
        return None

    def result(self, ins):
        if self.seed is None:
            return None
        if self.contract[3] == 8:
            return self.load(ins)
        ops = ins.operands
        if self.heap_fixed and ins.id == a.ARM64_INS_ADD and len(ops) == 3 and all(o.type == a.ARM64_OP_REG for o in ops) and self.width(ins, ops[0].reg) == self.width(ins, ops[1].reg) == 64 and ins.reg_name(ops[2].reg) == 'x28' and not ops[2].ext and ops[2].shift.type == a.ARM64_SFT_LSL and ops[2].shift.value == 32:
            return self.packed.get(self.number(ins, ops[1].reg))
        return None

    def result_index(self, ins):
        if not self.input_binding or self.result(ins) is None:
            return None
        if self.contract[3] == 8:
            return (self.address(ins, ins.operands[1])-self.contract[2]) // self.contract[3]
        return self.packed_indices.get(self.number(ins, ins.operands[1].reg))

    def step(self, state, ins, writes, memory_write):
        if self.seed is None:
            return
        sp = state[15]
        self.roots = {k for k in self.roots if sp[0] == STACK and sp[2] == 0 and k >= self.signed(sp[1])}
        self.words = {k: v for k, v in self.words.items() if sp[0] == STACK and sp[2] == 0 and k >= self.signed(sp[1])}
        if ins.group(cs.CS_GRP_CALL) or ins.group(cs.CS_GRP_INT) or ins.id in (a.ARM64_INS_DC, a.ARM64_INS_SYS, a.ARM64_INS_SYSL):
            self.clear()
            return
        ops = ins.operands
        dst = self.number(ins, ops[0].reg) if ops and ops[0].type == a.ARM64_OP_REG else -1
        alias = packed = packed_index = None
        if ins.id == a.ARM64_INS_MOV and len(ops) == 2 and dst >= 0 and ops[1].type == a.ARM64_OP_REG and self.width(ins, ops[0].reg) == self.width(ins, ops[1].reg):
            src = self.number(ins, ops[1].reg)
            if self.width(ins, ops[0].reg) == 64:
                alias = self.aliases.get(src)
            packed = self.packed.get(src)
            packed_index = self.packed_indices.get(src)
        if ins.id in (a.ARM64_INS_ADD, a.ARM64_INS_SUB) and len(ops) == 3 and dst >= 0 and ops[1].type == a.ARM64_OP_REG and self.width(ins, ops[0].reg) == self.width(ins, ops[1].reg) == 64 and ops[2].type == a.ARM64_OP_IMM and 0 <= ops[2].imm <= 4095 and not ops[2].shift.type:
            src = self.aliases.get(self.number(ins, ops[1].reg))
            if src is not None:
                at = src + (ops[2].imm if ins.id == a.ARM64_INS_ADD else -ops[2].imm)
                if -4096 <= at <= 4096:
                    alias = at
        if self.contract[3] == 4:
            value = self.load(ins)
            if value is not None:
                packed = value
                if self.input_binding:
                    packed_index = (self.address(ins, ops[1])-self.contract[2]) // self.contract[3]
        if ins.id in (a.ARM64_INS_LDR, a.ARM64_INS_LDUR) and len(ops) == 2 and dst >= 0 and self.width(ins, ops[0].reg) == 64 and ops[1].type == a.ARM64_OP_MEM and not ins.writeback:
            base = self.read_reg(state, ins, ops[1].mem.base)
            if base[0] == STACK and base[2] == 0 and not ops[1].mem.index and self.signed(base[1]) + ops[1].mem.disp in self.roots:
                alias = 0
        for memory in ops:
            if memory.type != a.ARM64_OP_MEM or not memory_write(ins, memory):
                continue
            base = self.read_reg(state, ins, memory.mem.base)
            width = self.width(ins, ops[0].reg) // 8 if ops and ops[0].type == a.ARM64_OP_REG else 0
            if ins.id in (a.ARM64_INS_STRB, a.ARM64_INS_STURB): width = 1
            if ins.id in (a.ARM64_INS_STRH, a.ARM64_INS_STURH): width = 2
            count = 2 if ins.id == a.ARM64_INS_STP else 1
            plain = ins.id in (a.ARM64_INS_STR, a.ARM64_INS_STUR, a.ARM64_INS_STP, a.ARM64_INS_STRB, a.ARM64_INS_STURB, a.ARM64_INS_STRH, a.ARM64_INS_STURH)
            at, stack_at = self.address(ins, memory), self.signed(base[1]) + memory.mem.disp
            own_frame_writeback = False
            if self.input_binding and ins.writeback and self.number(ins, memory.mem.base) == 15 and base[0] == STACK and base[2] == 0 and width and plain:
                j = next(i for i, op in enumerate(ops) if op.type == a.ARM64_OP_MEM)
                post = j+2 == len(ops) and ops[j+1].type == a.ARM64_OP_IMM
                if post or j+1 == len(ops):
                    updated = self.signed(base[1]) + (ops[j+1].imm if post else memory.mem.disp)
                    own_frame_writeback = -(1 << 20) <= updated <= 0 and min(self.signed(base[1]), updated) <= stack_at <= -count*width
            if base[0] == STACK and base[2] == 0 and (not ins.writeback or own_frame_writeback) and not memory.mem.index and plain and width and -(1 << 63) <= stack_at <= (1 << 63) - 1 - count * width:
                self.roots.difference_update(k for k in tuple(self.roots) if stack_at < k+8 and k < stack_at+count*width)
                self.words = {k: v for k, v in self.words.items() if not (stack_at < k+8 and k < stack_at+count*width)}
                if width == 8:
                    for part in range(count):
                        value = self.read_reg(state, ins, ops[part].reg)
                        if value[0] == WORD and len(self.words) < 64:
                            self.words[stack_at+part*8] = value[1]
                        if self.aliases.get(self.number(ins, ops[part].reg)) == 0 and len(self.roots) < 64:
                            self.roots.add(stack_at+part*8)
            elif at is not None and plain and width and self.contract[2] <= at <= self.contract[2]+self.seed[1]*self.contract[3]-count*width:
                self.cells = {k: v for k, v in self.cells.items() if not (at < k+self.contract[3] and k < at+count*width)}
                if width == self.contract[3] and (at-self.contract[2]) % width == 0:
                    for part in range(count):
                        src = self.number(ins, ops[part].reg)
                        value = state[src][1] if src >= 0 and state[src][0] == OBJECT else self.packed.get(src) if width == 4 else None
                        if value is not None:
                            self.cells[at+part*width] = value
            else:
                self.clear()
                return
        for reg in writes:
            self.aliases.pop(reg, None)
            self.packed.pop(reg, None)
            self.packed_indices.pop(reg, None)
        if dst >= 0 and dst in writes:
            if alias is not None: self.aliases[dst] = alias
            if packed is not None: self.packed[dst] = packed
            if packed_index is not None: self.packed_indices[dst] = packed_index

    @staticmethod
    def signed(value):
        return value - (1 << 64) if value >> 63 else value
