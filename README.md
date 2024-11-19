![Render - zkTLS Mina zkApp](https://github.com/user-attachments/assets/493c8d03-ea64-4b9a-a552-d2843aa16107)

# zkTLS Mina zkApp | ZKON

This repository hosts the zkApps that drive the ZKON Oracle ecosystem on the Mina blockchain. Through our innovative zkTLS Oracle, developers can securely make onchain requests, enabling the seamless integration of provable data sourced from offchain HTTPS connections. The zkTLS Oracle facilitates privacy-preserving transactions, ensuring that sensitive data can be verified without exposure.

> ⚠️ ***Warning*: This is a devnet version, not audited and not ready for mainnet yet.**

## How to build

```sh
npm run build
```

## How to run tests

```sh
npm run test
npm run testw # watch mode
```

## How to run coverage

```sh
npm run coverage
```

## How to use it from your zkapp

Version v0.0.1-preview

### Devnet Addresses

**ZkonCoordinator**

B62qnmsn4Bm4MzPujKeN1faxedz4p1cCAwA9mKAWzDjfb4c1ysVvWeK

### Setup

You will need o1.js version 1.2.0.

Then add the ZKON lib as a dependency in your zkapp project. 
package.json

```json
  "dependencies": {
    "zkon-zkapp": "git://github.com/ZKON-Network/zkTLS-Mina-zkApp.git#devnet"
  }
```

You will need to manually compile the mina-fungible-token dep. To do so create a file called build-mina-fungible-token.js in the root with the following content:

```js
import * as fs from 'fs';

const configFile = 'node_modules/mina-fungible-token/tsconfig.json';
const content = JSON.parse(fs.readFileSync(configFile));
delete content.compilerOptions.typeRoots;
fs.writeFileSync(configFile, JSON.stringify(content, null, 4));
```


Then modify your package.json to execute the file after the installation.

```json
  "scripts": {
    "prepare": "node build-mina-fungible-token.js && cd node_modules/mina-fungible-token && npm run build"
  },
```

Import the deps in your zkapp

```tsx
import { ZkonZkProgram, ZkonRequestCoordinator, ExternalRequestEvent } from 'zkon-zkapp';
```

### Coding

Important note: We don't actually support import extrernal deps other than the ones from zkon-zkapp and the o1.js. We're working on upgrading this. 

Inside your zkapp call the sendRequest method of the coordinator, you will need to send your zkapp address and an ipfs hash (divided in two parts) with the json request. Will explain more later on the format. 

Optionally you can send a fourth parameter, the nonce, which allow multiple request on the same block.

```tsx
  @method.returns(Field)
  async sendRequest(hashPart1: Field, hashPart2: Field) {
    const coordinator = new ZkonRequestCoordinator(coordinatorAddress);
    
    const requestId = await coordinator.sendRequest(this.address, hashPart1, hashPart2);

    const event = new ExternalRequestEvent({
      id: requestId,
      hash1: hashPart1,
      hash2: hashPart2,      
    });
    
    this.emitEvent('requested', event);

    return requestId;
  }
```

Note: It's important to emit the ExternalRequestEvent in your zkapp, if not the oracle will not respond to your requests. 

Then add a callback method for receiving the response, call it “receiveZkonResponse”:

```tsx
  @method
  async receiveZkonResponse(requestId: Field, proof: ZkonProof) {
    const coordinator = new ZkonRequestCoordinator(coordinatorAddress);
    await coordinator.recordRequestFullfillment(requestId, proof);
    this.response.set(proof.publicInput.dataField); 
  }
```

Note: Don't forget to call “recordRequestFullfillment” to ensure that the proof is correct.

Note 2: Don't forget to export default your ZkApp. 

### IPFS Request

For requesting the offchain data you will need to create a json with the following format: 

```json
{
  "method": "GET",
  "baseURL": "api.kucoin.com/api/v1/market/stats?symbol=BTC-USDT",
  "path": "data,averagePrice",
  "zkapp": "your zkapp compiled in js"
}
```

Now you can upload the JSON to IPFS.

And here is a sample code on how to convert a IPFS hash to two Fields:

```tsx
import { StringCircuitValue } from 'zkon-zkapp';

function segmentHash(ipfsHashFile: string) {
    const ipfsHash0 = ipfsHashFile.slice(0,30) // first part of the ipfsHash
    const ipfsHash1 = ipfsHashFile.slice(30) // second part of the ipfsHash
      
    const field1 = new StringCircuitValue(ipfsHash0).toField();
    
    const field2 = new StringCircuitValue(ipfsHash1).toField();
  
    return {field1, field2}
}
```

### Prepay for the requests

Note: For devnet there is no need to prepay for the requests.

Before doing any request you should prepay it with ZKON tokens. Call the "prepayRequest" method from the ZkonCoordinator, sending how many request you want to prepay and your zkapp public key as beneficiary (or any zkapp you may want to prepay request for).

```tsx
  @method 
  async prepayRequest(requestAmount: UInt64, beneficiary: PublicKey) {}
```

## License

[Apache-2.0](LICENSE)
