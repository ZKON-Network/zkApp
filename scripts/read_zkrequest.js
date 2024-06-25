import dotenv from 'dotenv';
dotenv.config();
import {    
    Mina,
    fetchAccount,
    PublicKey,
  } from 'o1js';
import fs from 'fs-extra';
    
  // Network configuration
  const useCustomLocalNetwork = process.env.USE_CUSTOM_LOCAL_NETWORK === 'true';  
  const network = Mina.Network({
    mina: useCustomLocalNetwork
      ? 'http://localhost:8080/graphql'
      : 'https://api.minascan.io/node/devnet/v1/graphql',
    lightnetAccountManager: 'http://localhost:8181',
    // archive: useCustomLocalNetwork
    // ? '' : 'https://api.minascan.io/archive/devnet/v1/graphql',
  });
  Mina.setActiveInstance(network);

  let localData;

  // Fee payer setup
  localData = fs.readJsonSync('./data/addresses.json');
  const zkRequestAddress = localData.zkRequestAddress;

  // zkApps deployment
  console.log(`Reading from zkApp in ${zkRequestAddress}`);
  console.log('Fetching zkAppAccount...');
  const accountInfo = await fetchAccount({publicKey: zkRequestAddress, network});
  
  if (accountInfo.account.zkapp) {
    const zkAppState = accountInfo.account.zkapp;
    const field1 =  zkAppState.appState[0];
    const field2 =  zkAppState.appState[1];
    console.log('zkApp State:', PublicKey.fromFields([field1,field2]).toBase58() );
  } else {
    console.log('No zkApp found for the given public key.');
  }