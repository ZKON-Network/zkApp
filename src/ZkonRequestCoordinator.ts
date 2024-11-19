import { Field, SmartContract, state, State, method, PublicKey, Poseidon, UInt64, Struct, assert, Proof, DeployArgs, ZkProgram, UInt32 } from 'o1js';
import { FungibleToken } from 'mina-fungible-token';
import { ZkonZkProgram } from './zkProgram.js';

export interface CoordinatorDeployProps extends Exclude<DeployArgs, undefined> {
  oracle : PublicKey
  zkonToken : PublicKey
  owner : PublicKey
  feePrice : UInt64
}

class RequestEvent extends Struct ({
  id: Field,
  hash1: Field,
  hash2: Field,
  senderX: Field,
  senderY: Field
}) {}

export class ExternalRequestEvent extends Struct ({
  id: Field,
  hash1: Field,
  hash2: Field  
}) {}

class RequestPaidEvent extends Struct ({
  zkApp: PublicKey,
  requestsPaid: Field,
  createdAt: UInt32
}) {}

export let ZkonProof_ = ZkProgram.Proof(ZkonZkProgram);
export class ZkonProof extends ZkonProof_ {}

export class ZkonRequestCoordinator extends SmartContract {
  @state(PublicKey) oracle = State<PublicKey>();
  @state(PublicKey) zkonToken = State<PublicKey>();
  @state(PublicKey) owner = State<PublicKey>();
  @state(UInt64) feePrice = State<UInt64>();
  @state(UInt64) requestCount = State<UInt64>();

  async deploy(props: CoordinatorDeployProps) {
    await super.deploy(props);
    this.oracle.set(props.oracle);
    this.zkonToken.set(props.zkonToken);
    this.owner.set(props.owner);
    this.feePrice.set(props.feePrice);
    this.requestCount.set(new UInt64(1));
  }

  onlyOwner() {
    const currentOwner = this.owner.getAndRequireEquals();
    currentOwner.assertEquals(this.sender.getAndRequireSignatureV2());
  }

  @method 
  async setFeePrice(feePrice: UInt64) {
    this.onlyOwner();
    this.feePrice.set(feePrice);
  }

  @method 
  async setOwner(owner: PublicKey) {
    this.onlyOwner();
    this.owner.set(owner);
  }

  @method 
  async setToken(zkonToken: PublicKey) {
    this.onlyOwner();
    this.zkonToken.set(zkonToken);
  }

  events = {
    requested: RequestEvent,
    fullfilled: Field,
    requestsPaid: RequestPaidEvent
  };

  @method.returns(Field)
  async sendRequest(requester: PublicKey,hash1: Field, hash2: Field, nonce: Field = Field(1)) {
   
    const currentRequestCount = this.requestCount.getAndRequireEquals();    
    const requestId = Poseidon.hash([currentRequestCount.toFields()[0], requester.toFields()[0], nonce])
    const sender = requester.toFields();

    const event = new RequestEvent({
      id: requestId,
      hash1: hash1,
      hash2: hash2,
      senderX: sender[0],
      senderY: sender[1]
    });

    this.emitEvent('requested', event);
    
    this.requestCount.set(currentRequestCount.add(1));

    return requestId;
  }  

  @method 
  async prepayRequest(requestAmount: UInt64, beneficiary: PublicKey) {
    
    const ZkToken = new FungibleToken(this.zkonToken.getAndRequireEquals());    
    
    const feePrice = this.feePrice.getAndRequireEquals();
    const totalAmount = feePrice.mul(requestAmount);

    await ZkToken.transfer(this.sender.getAndRequireSignatureV2(), this.owner.getAndRequireEquals(), totalAmount);
    
    //Get the Blockchain length
    const createdAt = this.self.network.blockchainLength
    
    const event = new RequestPaidEvent({
      zkApp: beneficiary,
      requestsPaid: requestAmount.toFields()[0],
      createdAt: createdAt.getAndRequireEquals()
    });

    this.emitEvent('requestsPaid', event);    
  }  

  @method
  async recordRequestFullfillment(requestId: Field, proof: ZkonProof) {
    // Assert caller is the oracle
    const caller = this.sender.getAndRequireSignatureV2();
    caller.assertEquals(this.oracle.getAndRequireEquals());

    await proof.verify();
    
    this.emitEvent('fullfilled', requestId);
  }
}

export default ZkonRequestCoordinator;