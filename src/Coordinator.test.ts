import {
  Field,
  Mina,
  PrivateKey,
  PublicKey,
  AccountUpdate,
  UInt64,
  Poseidon,
  provablePure,
  UInt8,
  fetchAccount,
} from 'o1js';
import { FungibleToken, FungibleTokenAdmin } from 'mina-fungible-token';
import { ZkonRequestCoordinator } from './ZkonRequestCoordinator.js';
import { StringCircuitValue } from './String.js';


let proofsEnabled = false;

describe('Zkon Token Tests', () => {
  let deployerAccount: PublicKey,
    deployerKey: PrivateKey,
    requesterAccount: PublicKey,
    requesterKey: PrivateKey,
    zktAddress: PublicKey,
    zktPrivateKey: PrivateKey,
    token: FungibleToken,
    zkCoordinatorAddress: PublicKey,
    zkCoordinatorPrivateKey: PrivateKey,
    coordinator: ZkonRequestCoordinator,
    tokenId: Field,
    feePrice: UInt64,
    treasuryAddress: PublicKey,
    treasuryPrivateKey: PrivateKey,
    oracleAddress: PublicKey,
    oracleKey: PrivateKey,
    randomUserAddress: PublicKey,
    randomUserKey: PrivateKey,
    ipfsHash: string,
    tokenAdmin: Mina.TestPublicKey,
    tokenAdminContract: FungibleTokenAdmin;

  beforeAll(async () => {
    if (proofsEnabled) await FungibleToken.compile();
  });

  beforeEach((done) => {
    Mina.LocalBlockchain({ proofsEnabled }).then((Local) => {
      Mina.setActiveInstance(Local);
      deployerKey = Local.testAccounts[0].key;
      deployerAccount = Local.testAccounts[0];
      requesterAccount = Local.testAccounts[1];
      requesterKey = Local.testAccounts[1].key;
      tokenAdmin = Local.testAccounts[2];
      oracleKey = Local.testAccounts[3].key;
      oracleAddress = Local.testAccounts[3];
      randomUserKey = Local.testAccounts[4].key;
      randomUserAddress = Local.testAccounts[4];
      zktPrivateKey = PrivateKey.random();
      zktAddress = zktPrivateKey.toPublicKey();
      token = new FungibleToken(zktAddress);
      tokenId = token.deriveTokenId();

      zkCoordinatorPrivateKey = PrivateKey.random();
      zkCoordinatorAddress = zkCoordinatorPrivateKey.toPublicKey();
      coordinator = new ZkonRequestCoordinator(zkCoordinatorAddress);

      treasuryPrivateKey = PrivateKey.random();
      treasuryAddress = zkCoordinatorPrivateKey.toPublicKey();

      // oracleKey = PrivateKey.random();
      // oracleAddress = oracleKey.toPublicKey();

      feePrice = new UInt64(10000);

      tokenAdminContract = new FungibleTokenAdmin(tokenAdmin);

      ipfsHash = 'QmbCpnprEGiPZfESXkbXmcXcBEt96TZMpYAxsoEFQNxoEV'; //Mock JSON Request
      done();
    });
  });

  async function localDeploy() {
    const txn = await Mina.transaction(
      {
        sender: deployerAccount,
        fee: 1e8,
      },
      async () => {
        AccountUpdate.fundNewAccount(deployerAccount, 2);
        await tokenAdminContract.deploy({
          adminPublicKey: tokenAdmin,
        })
        await token.deploy({
          admin: tokenAdmin,
          symbol: 'ZKON',
          src: '',
          decimals: UInt8.from(9),
        });
        await coordinator.deploy({
          oracle: oracleAddress,
          zkonToken: zktAddress,
          owner: deployerAccount,
          feePrice: feePrice
        });
      }
    );
    // this tx needs .sign(), because `deploy()` adds an account update that requires signature authorization
    (
      await txn
        .sign([deployerKey, zktPrivateKey, tokenAdmin.key ,zkCoordinatorPrivateKey])
        .prove()
    ).send();
  }

  it('Deploy & init coordinator', async () => {
    await localDeploy();
  });

  it('Send request', async () => {
    await localDeploy();

    const initialSupply = new UInt64(1000);

    let tx = await Mina.transaction(
      {
        sender: deployerAccount,
        fee: 1e8,
      },
      async () => {
        AccountUpdate.fundNewAccount(deployerAccount, 1);
        await token.mint(requesterAccount, initialSupply);
      }
    );
    tx.sign([deployerKey, tokenAdmin.key]);
    await tx.prove();
    await tx.send();

    let requesterBalance = (await token.getBalanceOf(requesterAccount)).toString();
    
    expect(requesterBalance).toEqual(initialSupply.toString());

    const ipfsHashSegmented0 = segmentHash(ipfsHash);

    const txn = await Mina.transaction(
      {
        sender: requesterAccount,
        fee: 1e8,
      },
      async () => {
        await coordinator.sendRequest(
          deployerAccount,
          ipfsHashSegmented0.field1,
          ipfsHashSegmented0.field2
        );
      }
    );
    txn.sign([requesterKey, deployerKey]);
    await txn.prove();
    await txn.send();
    
    const events = await coordinator.fetchEvents();
    expect(events[0].type).toEqual('requested');
    const requestEvent = provablePure(events[0].event.data).toFields(
      events[0].event.data
    );
    const expectedRequestId = Poseidon.hash([
      Field(1),
      deployerAccount.toFields()[0],
    ]);
    expect(requestEvent[0]).toEqual(expectedRequestId);
    expect(requestEvent[1]).toEqual(ipfsHashSegmented0.field1);
    expect(requestEvent[2]).toEqual(ipfsHashSegmented0.field2);
    const dehashed = PublicKey.fromFields([requestEvent[3], requestEvent[4]]);
    expect(dehashed.toBase58()).toEqual(deployerAccount.toBase58());

    await fetchAccount({publicKey: oracleAddress});
    console.log("Oracle Address: ", oracleAddress.toBase58())
    // const fullfillTxn = await Mina.transaction(
    //   {
    //     sender: oracleAddress,
    //     fee: 1e8,
    //   },
    //   async () => {
    //     await coordinator.recordRequestFullfillment(expectedRequestId);
    //   }
    // );
    // await fullfillTxn.prove();
    // await (await fullfillTxn.sign([oracleKey]).send()).wait;

    // const newEvents = await coordinator.fetchEvents();
    // console.log(newEvents)
    // expect(newEvents.some((e) => e.type === 'fullfilled')).toEqual(true);

  });

  it('Set fees', async () => {
    await localDeploy();    
    let tx = await Mina.transaction(
      {
        sender: deployerAccount,
        fee: 1e8,
      },
      async () => {        
        await coordinator.setFeePrice(new UInt64(100));
      }
    );
    tx.sign([deployerKey]);
    await tx.prove();
    await tx.send();

    let fees = await coordinator.feePrice.get();
    expect(fees).toEqual(new UInt64(100))

    let secondTx = await Mina.transaction(
      {
        sender: deployerAccount,
        fee: 1e8,
      },
      async () => {        
        await coordinator.setFeePrice(new UInt64(200));
      }
    );
    secondTx.sign([deployerKey]);
    await secondTx.prove();
    await secondTx.send();

    fees = await coordinator.feePrice.get();
    expect(fees).toEqual(new UInt64(200))

    try {
      let failedTx = await Mina.transaction(
        {
          sender: randomUserAddress,
          fee: 1e8,
        },
        async () => {        
          await coordinator.setFeePrice(new UInt64(100));
        }
      );
      failedTx.sign([randomUserKey]);
      await failedTx.prove();
      await failedTx.send();
      
    } catch (error) {
      console.log("Transaction failed as expected");
      fees = await coordinator.feePrice.get();
      expect(fees).toEqual(new UInt64(200))
    }
  });

  it('Set owner', async () => {
    await localDeploy();
    await fetchAccount({ publicKey: zkCoordinatorAddress });
    const initialOwner = await coordinator.owner.get();
    console.log('Initial owner: ', initialOwner.toBase58());
    try {
      //Can't change owner if not current owner
      let tx = await Mina.transaction(
        {
          sender: randomUserAddress,
          fee: 1e8,
        },
        async () => {
          await coordinator.setOwner(deployerAccount);
        }
      );
      tx.sign([randomUserKey]);
      await tx.prove();
      await tx.send();
    } catch (error) {
      //Set new owner (randomUser) by current owner (deployer)
      let tx = await Mina.transaction(
        {
          sender: deployerAccount,
          fee: 1e8,
        },
        async () => {
          await coordinator.setOwner(randomUserAddress);
        }
      );
      tx.sign([deployerKey]);
      await tx.prove();
      await tx.send();
    }

    const finalOwner = await coordinator.owner.get();
    console.log('Final owner: ', finalOwner.toBase58());
    expect(finalOwner.toBase58()).toEqual(randomUserAddress.toBase58())
  });

  it('Set token', async () => {
    await localDeploy();
    await fetchAccount({ publicKey: zkCoordinatorAddress });
    const newToken = PrivateKey.random().toPublicKey();
    try {
      //Can't change token if not current owner
      let tx = await Mina.transaction(
        {
          sender: randomUserAddress,
          fee: 1e8,
        },
        async () => {
          await coordinator.setToken(newToken);
        }
      );
      tx.sign([randomUserKey]);
      await tx.prove();
      await tx.send();
    } catch (error) {
      //Set new token address by current owner (deployer)
      let tx = await Mina.transaction(
        {
          sender: deployerAccount,
          fee: 1e8,
        },
        async () => {
          await coordinator.setToken(newToken);
        }
      );
      tx.sign([deployerKey]);
      await tx.prove();
      await tx.send();
    }

    const finalToken = await coordinator.zkonToken.get();
    expect(finalToken.toBase58()).toEqual(newToken.toBase58());
  });

  function segmentHash(ipfsHashFile: string) {
    console.log('SEGMENT');
    const ipfsHash0 = ipfsHashFile.slice(0, 29); // first part of the ipfsHash
    const ipfsHash1 = ipfsHashFile.slice(29); // second part of the ipfsHash
    console.log('ipfsHash0', ipfsHash0);
    const field1 = new StringCircuitValue(ipfsHash0).toField();
    console.log('ipfsHash0 2', StringCircuitValue.fromField(field1).toString());

    console.log('ipfsHash1', ipfsHash1);
    const field2 = new StringCircuitValue(ipfsHash1).toField();
    console.log('ipfsHash1 2', StringCircuitValue.fromField(field2).toString());

    const hash1 = StringCircuitValue.fromField(field1).toString().replace(/\0/g, '')
    const hash2 = StringCircuitValue.fromField(field2).toString().replace(/\0/g, '')
    console.log('final hash re', hash1.concat(hash2));
    console.log('final hash', ipfsHash0.concat(ipfsHash1));
    return { field1, field2 };
  }
});
