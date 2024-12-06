import { Mina, Field, ZkProgram, Struct, createEcdsaV2, createForeignCurveV2,Crypto, Bool, Bytes, UInt8, ForeignCurveV2,Provable,assert} from 'o1js';

// default bigint limb size
const l = 88n;

//Helper-classes
class Bytes32 extends Bytes(32) {};
class Secp256k1 extends createForeignCurveV2(Crypto.CurveParams.Secp256k1) {}
class Ecdsa extends createEcdsaV2(Secp256k1) {}

/** Taken from [o1js](https://github.com/o1-labs/o1js/blob/996ebb3119ec087a0badc16ea8036766cb68d3fb/src/lib/provable/crypto/foreign-ecdsa.ts#L288)
 * 
*/
function keccakOutputToScalar(hash: Bytes, Curve: typeof ForeignCurveV2) {
  const L_n = Curve.Scalar.sizeInBits;
  assert(L_n === 256, `Scalar sizes ${L_n} !== 256 not supported`);
  assert(hash.length === 32, `hash length ${hash.length} !== 32 not supported`);
  assert(l === 88n);
  let x2 = bytesToLimbBE(hash.bytes.slice(0, 10));
  let x1 = bytesToLimbBE(hash.bytes.slice(10, 21));
  let x0 = bytesToLimbBE(hash.bytes.slice(21, 32));

  return new Curve.Scalar.AlmostReduced([x0, x1, x2]);
}

/** Taken from [o1js](https://github.com/o1-labs/o1js/blob/996ebb3119ec087a0badc16ea8036766cb68d3fb/src/lib/provable/crypto/foreign-ecdsa.ts#L307)
 * 
*/
function bytesToLimbBE(bytes_: UInt8[]) {
  let bytes = bytes_.map((x) => x.value);
  let n = bytes.length;
  let limb = bytes[0];
  for (let i = 1; i < n; i++) {
    limb = limb.mul(1n << 8n).add(bytes[i]);
  }
  return limb.seal();
}

/**
 * This function checks the Bypte32 messageHash
 *
 * Ensures:
 * 1. The messageHash is not zero-hash.
 * 2. The length(messageHash) === 32.
 *
 * @param bytes_ - The byte array.
 * @returns A `bool(true)` if both `asserts` are true. Else panics
 */
function checkHash(bytes_: UInt8[]): Bool {

  let checkZero=Field(0);
  //Provable.log("CheckZero-pre-check:",checkZero)

  //Iterates over the UInt8[] of hash, and checks for no of 0 elements
  let bytes = bytes_.map((x)=> {
      //Provable.log(x.value, x.value.equals(0))
      const check = x.value.equals(Field(0))

      //Proveable.if() -> Behaves like ternary opreator.
      const checkZeroInt = Provable.if(
          check,
          Field(1),
          Field(0)
      )
      //Provable.log("Inside Map:", checkZeroInt)
      checkZero = checkZero.add(checkZeroInt);
      return x
  })

  //If zeroElements == 32, then throw Error, ZeroHash
  //Provable.log("CheckZero:",checkZero);
  assert(checkZero.lessThan(32), "Zero-hash!")
  Provable.log("Check: Hash is not a zero-hash!")

  let n = bytes.length;
  //If length of hash > 32, throw error.
  assert(n === 32, "Length greater than 32!")
  Provable.log("Check: Hash of correct size!")

  return Bool(true)
}

class ECDSAHelper extends Struct({
  messageHash: Bytes32, //Another type-check with basically ensures the hash is always 32 bytes.
  signature: Ecdsa,
  publicKey: Secp256k1
}){}

class PublicArgumets extends Struct({
    commitment: Field,
    dataField:Field
  }){}

const ZkonZkProgram = ZkProgram({
    name:'zkon-proof',
    publicInput: PublicArgumets,
  
    methods:{
      verifySource:{
        privateInputs: [Field, ECDSAHelper], 
        async method (
          commitment: PublicArgumets,
          decommitment: Field,
          ECDSASign:ECDSAHelper,
        ){
          checkHash(ECDSASign.messageHash.bytes).assertEquals(true, "Invalid Message Hash!")
          decommitment.assertEquals(commitment.commitment,"Response from proof-server invalid.");
          const checkSignature = ECDSASign.signature.verifySignedHashV2(
            keccakOutputToScalar(ECDSASign.messageHash, Secp256k1), 
            ECDSASign.publicKey)
          
          checkSignature.assertEquals(true,"Signature Verification Invalid!")
        }
      }
    }
  });

  export {ZkonZkProgram , PublicArgumets ,ECDSAHelper};
