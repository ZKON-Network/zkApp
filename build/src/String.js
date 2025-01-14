import { Field, Poseidon, Struct } from 'o1js';
import { UInt8 } from './UInt8.js';
const MAX_CHARS = 2 ** 5;
export class StringCircuitValue extends Struct({ value: [UInt8] }) {
    constructor(data) {
        if (data.length > MAX_CHARS) {
            throw new Error("string cannot exceed character limit");
        }
        const intArray = data.split('').map(x => UInt8.fromNumber(x.charCodeAt(0)));
        super({ value: intArray });
    }
    repr() {
        return this.value.map(x => x.toNumber());
    }
    toString() {
        return this.value.map((x) => String.fromCharCode(Number(x.toString()))).join('');
    }
    toBits() {
        const bits = [];
        this.value.forEach((uint) => {
            uint.toBits().forEach(bit => bits.push(bit));
        });
        return bits;
    }
    toField() {
        const values = this.value.map(x => x.value);
        let field = Field(0);
        for (let i = 0, b = Field(1); i < Math.min(values.length, 31); i++, b = b.mul(256)) {
            field = field.add(values[i].mul(b));
        }
        return field;
    }
    static fromField(field) {
        let values = [];
        const bits = field.toBits();
        const uint8Array = new Uint8Array(bits.length / 8);
        for (let i = 0; i < uint8Array.length; i++) {
            for (let bitIndex = 0; bitIndex < 8; bitIndex++) {
                if (bits[i * 8 + bitIndex].toBoolean()) {
                    uint8Array[i] |= 1 << bitIndex;
                }
            }
        }
        const stringVal = new StringCircuitValue('');
        for (let uint8 of uint8Array) {
            values.push(new UInt8({ value: new Field(uint8) }));
        }
        stringVal.value = values;
        return stringVal;
    }
    static fromBits(bits) {
        let nativeBits = [];
        if (typeof (bits[0]) != 'boolean') {
            nativeBits = bits.map((x) => x.toBoolean());
        }
        const intArray = [];
        for (let i = 0; i < nativeBits.length; i += 8) {
            const bitSubArray = nativeBits.slice(i, i + 8);
            const uint = UInt8.fromBits(bitSubArray);
            intArray.push(uint);
        }
        const stringVal = new StringCircuitValue('');
        stringVal.value = intArray;
        return stringVal;
    }
    hash() {
        return Poseidon.hash(this.value.map(x => Field(x.toString())));
    }
}
//# sourceMappingURL=String.js.map