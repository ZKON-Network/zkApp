import { SmartContract, PublicKey, state, State, method, Field } from 'o1js';
import {ZkonRequestCoordinator} from './ZkonRequestCoordinator';

export class ZkonRequest extends SmartContract {
  @state(PublicKey) coordinator = State<PublicKey>();
  @state(PublicKey) coinValue = State<Field>(); //Value of the coin returned by the oracle

  @method
  async initState(coordinator: PublicKey) {
    super.init();
    this.coordinator.set(coordinator);
  }

  /**
   * @notice Creates a request to the stored coordinator address
   * @param req The initialized Zkon Request
   * @return requestId The request ID
   */
  @method.returns(Field)
  async sendRequest(hashPart1: Field, hashPart2: Field) {
    const coordinatorAddress = this.coordinator.getAndRequireEquals();
    const coordinator = new ZkonRequestCoordinator(coordinatorAddress);
    
    return await coordinator.sendRequest(this.self.publicKey, hashPart1, hashPart2);
  }

  /**
   * @notice Validates the request
   */
  @method
  async setCoinValue(value: Field) {
    const coordinatorAddress = this.coordinator.getAndRequireEquals();
    const coordinator = new ZkonRequestCoordinator(coordinatorAddress);
    // assert(this.sender === coordinatorAddress) //Validates who is sending
    this.coinValue.set(value)
  }
}