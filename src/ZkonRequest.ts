import { SmartContract, PublicKey, state, State, method, Field, DeployArgs, Proof, Struct } from 'o1js';
import {ZkonRequestCoordinator, RequestEvent} from './ZkonRequestCoordinator.js';
import { Commitments } from './zkProgram.js';

export interface AppDeployProps extends Exclude<DeployArgs, undefined> {
  /** Address of the coordinator contract */
  coordinator: PublicKey  
}

export class ZkonRequest extends SmartContract {
  @state(PublicKey) coordinator = State<PublicKey>();
  @state(PublicKey) coinValue = State<Field>(); //Value of the coin returned by the oracle

  async deploy(props: AppDeployProps) {
    await super.deploy(props);
    this.coordinator.set(props.coordinator);
  }

  events = {
    requested: RequestEvent
  };

  /**
   * @notice Creates a request to the stored coordinator address
   * @param req The initialized Zkon Request
   * @return requestId The request ID
   */
  @method.returns(Field)
  async sendRequest(hashPart1: Field, hashPart2: Field) {
    const coordinatorAddress = this.coordinator.getAndRequireEquals();
    const coordinator = new ZkonRequestCoordinator(coordinatorAddress);
    
    const requestId = await coordinator.sendRequest(this.address, hashPart1, hashPart2);
    const sender = this.address.toFields();

    const event = new RequestEvent({
      id: requestId,
      hash1: hashPart1,
      hash2: hashPart2,
      senderX: sender[0],
      senderY: sender[1]
    });
    
    this.emitEvent('requested', event);

    return requestId;
  }

  /**
   * @notice Validates the request
   */
  @method
  async receiveZkonResponse(requestId: Field, proof: Proof<Commitments,void>,) {
    const coordinatorAddress = this.coordinator.getAndRequireEquals();
    const coordinator = new ZkonRequestCoordinator(coordinatorAddress);
    await coordinator.recordRequestFullfillment(requestId, proof);
    this.coinValue.set(proof.publicInput.response);
  }
}