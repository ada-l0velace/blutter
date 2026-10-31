"""Register-read provenance, independent of producer proof-address lists."""
from capstone import arm64 as a


def reads_result(ins, dependencies, number):
    reads = {number(ins, r) for r in ins.regs_access()[0]} - {-1}
    if ins.id == a.ARM64_INS_MOVK and ins.operands:
        reads.add(number(ins, ins.operands[0].reg))
    return any(dependencies & (1 << r) for r in reads)


def transfer(dependencies, writes, destination, produced, reads, state):
    for r in writes:
        dependencies &= ~(1 << r)
    if destination in writes and produced and reads:
        dependencies |= 1 << destination
    # Unknown class/value facts cannot support a published target use.
    return dependencies & sum(1 << r for r, value in enumerate(state) if value[0] != 0)
