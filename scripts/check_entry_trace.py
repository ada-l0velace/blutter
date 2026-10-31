"""Word-level first-entry predicates, independent of the native IR evaluator."""


def signed_field(word, read):
    # SBFM aliases: SBFX (non-wrapping) and SBFIZ (wrapping).
    if word & 0x7f800000 != 0x13000000:
        return None
    bits = 64 if word >> 31 else 32
    assert bool(word & (1 << 22)) == (bits == 64)
    rotate, end = (word >> 16) & 63, (word >> 10) & 63
    if rotate >= bits or end >= bits:
        return None
    source = read((word >> 5) & 31, bits)
    if source is None:
        return None
    if end >= rotate:
        length, value, shift = end-rotate+1, source >> rotate, 0
    else:
        length, value, shift = end+1, source, bits-rotate
    mask = (1 << length)-1
    value &= mask
    if value & (1 << (length-1)):
        value -= 1 << length
    return value << shift & ((1 << bits)-1)


def branch_condition(word, comparison, read):
    if word & 0xff000010 != 0x54000000 or word & 15 >= 14:
        return None
    bits = 64 if comparison >> 31 else 32
    mask = (1 << bits)-1
    left = read((comparison >> 5) & 31, bits)
    right = None
    if comparison & 0x7f20001f == 0x6b00001f:
        shift, kind, number = (comparison >> 10) & 63, (comparison >> 22) & 3, (comparison >> 16) & 31
        if shift >= bits or kind == 3:
            return None
        right = 0 if number == 31 else read(number, bits)
        if right is not None:
            right &= mask
            if kind == 0: right = right << shift & mask
            elif kind == 1: right >>= shift
            else:
                if right & (1 << (bits-1)): right -= 1 << bits
                right = right >> shift & mask
    elif comparison & 0x7f80001f == 0x7100001f:
        right = ((comparison >> 10) & 4095) << (12 if comparison & (1 << 22) else 0)
    if left is None or right is None:
        return None
    left &= mask
    right &= mask
    result = (left-right) & mask
    negative, zero, carry = bool(result & (1 << (bits-1))), result == 0, left >= right
    overflow = bool((left ^ right) & (left ^ result) & (1 << (bits-1)))
    return (zero, not zero, carry, not carry, negative, not negative, overflow, not overflow,
            carry and not zero, not carry or zero, negative == overflow, negative != overflow,
            not zero and negative == overflow, zero or negative != overflow)[word & 15]
