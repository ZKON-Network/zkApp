import { Bool, Field, Poseidon, Struct } from 'o1js';
import { UInt8 } from './UInt8.js';

const MAX_CHARS = 2 ** 5;

export class StringCircuitValue extends Struct({value: [UInt8]}) {

    constructor(data: string, values?: UInt8[]) {
        if (data) {
            if (data.length > MAX_CHARS - 3) {
                throw new Error("string must be "+(MAX_CHARS - 3)+" characters");
            }
            const intArray = data.split('').map(x => UInt8.fromNumber(x.charCodeAt(0)))
            super({value: intArray});
        } else if (values) {
            console.log('values length', values.length);
            if (values.length > 29) {
                throw new Error("values must be less or equal than "+(29)+" length");
            }
            super({value: values});
        } else {
            throw new Error("You must provide a string or a UInt8 array");
        }
    }

    repr(): number[] {
        return this.value.map(x => x.toNumber())
    }

    toString(): string {
        return this.value.map((x) => String.fromCharCode(Number(x.toString()))).join('')
    }

    toBits(): boolean[] {
        const bits: boolean[] = []
        this.value.forEach((uint) => {
            uint.toBits().forEach(bit => bits.push(bit));
        });
        return bits
    }

    toField(): Field {
        const values = this.value.map(x => x.value);
        
        // Start with the length as the first byte (position 1)
        let field = Field(values.length);

        // Begin with b = 256 for the first actual value in the array
        for (let i = 0, b = Field(256); i < Math.min(values.length, 31); i++, b = b.mul(256)) {
            field = field.add(values[i].mul(b));
        }
        
        return field;
    }

    static fromField(field: Field): StringCircuitValue {
        let values: UInt8[] = [];
        
        // Convert field to bits
        const bits = field.toBits();

        // Pad bits array to ensure length is a multiple of 8
        const paddingLength = (8 - (bits.length % 8)) % 8;
        for (let i = 0; i < paddingLength; i++) {
            bits.push(Bool(false)); // Add zero bits as padding
        }
    
        // We are dealing with bytes (8 bits at a time), so group the bits into bytes
        const byteArray = new Uint8Array(bits.length / 8);
    
        // Extract each byte from the bits array
        for (let i = 0; i < byteArray.length; i++) {
            let byteValue = 0;
            for (let bitIndex = 0; bitIndex < 8; bitIndex++) {
                if (bits[i * 8 + bitIndex].toBoolean()) {
                    byteValue |= 1 << bitIndex;
                }
            }
            byteArray[i] = byteValue;
        }
    
        // The first byte should be the length of the original string
        const length = byteArray[0];
    
        // Extract the actual values from the remaining bytes
        for (let i = 1; i <= length; i++) {
            values.push(new UInt8({ value: new Field(byteArray[i]) }));
        }
    
        return new StringCircuitValue('', values);
    }    

    static fromUint(values: UInt8[]): StringCircuitValue {
        return new StringCircuitValue('', values);
    }

    static fromBits(bits: Bool[]): StringCircuitValue {
        let nativeBits: boolean[] = [];
        if (typeof (bits[0]) != 'boolean') {
            nativeBits = bits.map((x: Bool) => x.toBoolean())
        }
        const intArray = []
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