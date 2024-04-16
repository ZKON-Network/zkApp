import { SmartContract, PublicKey, Struct, UInt64, Bytes, state, State, method, PrivateKey } from 'o1js';
import {ZkonRequestCoordinator} from './ZkonRequestCoordinator';
import {Zkon, Request} from './Zkon';

export class ZkonRequest extends SmartContract { 
  @state(PublicKey) coordinator = State<PublicKey>();

  @method
  initState(coordinator: PublicKey) {
    super.init();
    this.coordinator.set(coordinator);
  }

  /**
  * @notice Creates a request 
  * @param jobId The Job Specification ID that the request will be created for
  * @param callbackAddr address to operate the callback on
  * @param callbackFunctionSignature function signature to use for the callback
  * @return A Zkon Request struct in memory
  */ 
  buildRequest(jobId: UInt64,callbackAddr: PublicKey,callbackFunctionSignature: Bytes)
  {
    const zkon = new Zkon(PrivateKey.random().toPublicKey()) //Review
    return zkon.initialize(jobId, callbackAddr, callbackFunctionSignature);
  }

  /**
  * @notice Creates a request to the stored oracle address
  * @param req The initialized Zkon Request
  * @return requestId The request ID
  */
  @method
  async sendRequest(req: Request){
    const coordinatorAddress = this.coordinator.getAndRequireEquals();
    const coordinator = new ZkonRequestCoordinator(coordinatorAddress);

    await coordinator.sendRequest(req);
  }
}