// Run with: node scripts/test_frida_decoders.js
// Synthetic object bytes exercise decoder results without an app or device.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

class ScalarPointer {
    constructor(value) { this.value = value; }
    toInt32() { return Number(BigInt.asIntN(32, this.value)); }
}

class MemoryPointer {
    constructor(bytes, offset = 0) { this.bytes = bytes; this.offset = offset; }
    add(offset) { return new MemoryPointer(this.bytes, this.offset + offset); }
    readU32() { return this.bytes.readUInt32LE(this.offset); }
    readS64() { return this.bytes.readBigInt64LE(this.offset); }
    readU64() { return this.bytes.readBigUInt64LE(this.offset); }
    readPointer() { return new ScalarPointer(this.readU64()); }
}

// Class IDs and offsets here are deliberately synthetic.
const context = {
    console,
    CidObject: 1, CidNull: 2, CidSmi: 3, CidMint: 4, CidDouble: 5,
    CidBool: 6, CidString: 7, CidTwoByteString: 8, CidArray: 9,
    CidImmutableArray: 10, CidGrowableArray: 11,
    NumPredefinedCids: 100,
    Classes: [],
};
for (const [name, id] of Object.entries(context)) {
    if (name.startsWith('Cid')) context.Classes[id] = { id, name };
}
const template = fs.readFileSync(path.join(__dirname, 'frida.template.js'), 'utf8');
assert.equal(template.split('tryLoadLibapp();').length, 2);
vm.createContext(context);
vm.runInContext(template.replace('tryLoadLibapp();', ''), context);

let checked = 0;
for (const value of [0n, 1n, -1n, (1n << 63n) - 1n, -(1n << 63n)]) {
    const bytes = Buffer.alloc(16);
    bytes.writeBigInt64LE(value, 8);
    assert.equal(context.getDartMint(new MemoryPointer(bytes), { valOffset: 8 }), value);
    checked++;
}

for (const id of [context.CidArray, context.CidImmutableArray]) {
    for (const values of [[], [-3, 0, 5]]) {
        const bytes = Buffer.alloc(32);
        bytes.writeUInt32LE(values.length << 1, 4);
        values.forEach((value, index) => bytes.writeInt32LE(value << 1, 8 + index * 4));
        const cls = { id, name: 'SyntheticList', lenOffset: 4, dataOffset: 8 };
        const actual = context.getObjectValue(new MemoryPointer(bytes), cls);
        assert.equal(JSON.stringify(actual), JSON.stringify(values));
        checked++;
    }
}

console.log(JSON.stringify({ status: 'PASSED', cases: checked }));
