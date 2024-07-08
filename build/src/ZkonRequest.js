var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
import { SmartContract, PublicKey, state, State, method, Field, Proof } from 'o1js';
import { ZkonRequestCoordinator } from './ZkonRequestCoordinator.js';
export class ZkonRequest extends SmartContract {
    constructor() {
        super(...arguments);
        this.coordinator = State();
        this.coinValue = State(); //Value of the coin returned by the oracle
    }
    async deploy(props) {
        await super.deploy(props);
        this.coordinator.set(props.coordinator);
    }
    /**
     * @notice Creates a request to the stored coordinator address
     * @param req The initialized Zkon Request
     * @return requestId The request ID
     */
    async sendRequest(hashPart1, hashPart2) {
        const coordinatorAddress = this.coordinator.getAndRequireEquals();
        const coordinator = new ZkonRequestCoordinator(coordinatorAddress);
        return coordinator.sendRequest(this.address, hashPart1, hashPart2);
    }
    /**
     * @notice Validates the request
     */
    async receiveZkonResponse(requestId, proof) {
        const coordinatorAddress = this.coordinator.getAndRequireEquals();
        const coordinator = new ZkonRequestCoordinator(coordinatorAddress);
        await coordinator.recordRequestFullfillment(requestId, proof);
        this.coinValue.set(proof.publicInput.response);
    }
}
__decorate([
    state(PublicKey),
    __metadata("design:type", Object)
], ZkonRequest.prototype, "coordinator", void 0);
__decorate([
    state(PublicKey),
    __metadata("design:type", Object)
], ZkonRequest.prototype, "coinValue", void 0);
__decorate([
    method.returns(Field),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Field, Field]),
    __metadata("design:returntype", Promise)
], ZkonRequest.prototype, "sendRequest", null);
__decorate([
    method,
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Field, Proof]),
    __metadata("design:returntype", Promise)
], ZkonRequest.prototype, "receiveZkonResponse", null);
//# sourceMappingURL=ZkonRequest.js.map