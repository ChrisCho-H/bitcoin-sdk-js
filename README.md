## bitcoin-sdk-js

**✨Bitcoin Typescript SDK for Node, Browser and Mobile✨**

_Bitcoin is hard. Especially for those not familiar with crypto, it is even hard
to create a simple bitcoin transaction._

bitcoin-sdk-js provides various features which help to **create various type of bitcoin transaction so easily🚀**,
including **advanced smart contract like multisig, hashlock, timelock, combination of them, and even your own smart contract**.

## Install
``` bash
npm install bitcoin-sdk-js
```
## How To Use
``` javascript

import * as bitcoin from 'bitcoin-sdk-js';

// initialize Bitcoin Transaction object
const tx = new bitcoin.Transaction();

// add UTXO to spend as input
await tx.addInput({
  id: txId, // transaction id of utxo
  index: 0, // index of utxo in transaction
  value: value, // value of utxo(unit is bitcoin)
} as bitcoin.UTXO);

// add Target output to send Bitcoin
// most common transaction which sends bitcoin to single sig address
await tx.addOutput({
    address: await bitcoin.address.generateAddress(pubkey),
    value: value - fee, // value of utxo - fee
} as bitcoin.Target);

// sends bitcoin to 2-of-3 multisig transaction
await tx.addOutput({
    // all the smart contract output is recommended to use script address!
    address: await bitcoin.address.generateScriptAddress(
        // this generate multisig smart contract, which is possible up to 15-of-15 
        await bitcoin.script.generateMultiSigScript(2, [pubkey1, pubkey2, pubkey3]),
    ),
    value: value - fee, // value of utxo - fee
} as bitcoin.Target);

// sends bitcoin to single(or multi) sig script with timelock
await tx.addOutput({
    address: await bitcoin.address.generateScriptAddress(
        // able to spend this output after given block height
        (await bitcoin.script.generateTimeLockScript(2542622)) +
        // you can use generateMultiSigScript instead of single sig here
        (await bitcoin.script.generateSingleSigScript(pubkey)),
    ),
    value: value - fee, // value of utxo - fee
} as bitcoin.Target);

// sends bitcoin to single(or multi) sig script with hashlock
await tx.addOutput({
    address: await bitcoin.address.generateScriptAddress(
        // able to spend this output if 'secret' is given
        (await bitcoin.script.generateHashLockScript('secret')) + 
        // you can use generateMultiSigScript instead of single sig here
        (await bitcoin.script.generateSingleSigScript(pubkey)),
    ),
    value: value - fee, // value of utxo - fee
} as bitcoin.Target);

// sends bitcoin to single(or multi) sig script with timelock + hashlock
await tx.addOutput({
    address: await bitcoin.address.generateScriptAddress(
        /* 
        WATCH OUT! Order matters. You must place script in the order of
        timelock, hashlock and single(or multi) sig
        to spend this output with bitcoin-sdk-js
        */
        (await bitcoin.script.generateTimeLockScript(2542622)) +
        (await bitcoin.script.generateHashLockScript('secret')) +
        // you can use generateMultiSigScript instead of single sig here
        (await bitcoin.script.generateSingleSigScript(pubkey)),
    ),
    value: value - fee, // value of utxo - fee
} as bitcoin.Target);

// sends bitcoin to script with timelock + hashlock (no sig required)
await tx.addOutput({
    address: await bitcoin.address.generateScriptAddress(
        // if you only want hashlock, you can remove generateTimeLockScript
        (await bitcoin.script.generateTimeLockScript(2542622)) +
        (await bitcoin.script.generateHashLockScript('secret')),   
    ),
    value: value - fee, // value of utxo - fee
} as bitcoin.Target);

// if transaction use timelock input, must set tx locktime bigger than input timelock
tx.setLocktime(2542622);

// if input utxo only requires single sig(p2wpkh or p2pkh)
await tx.signInput(pubkey, privkey, 0);

// or if input utxo only requires multi sig(p2wsh or p2sh)
await tx.multiSignInput(
    [pubkey1, pubkey2, pubkey3],
    [privkey1, privkey2],
    0, // input index to sign
);

// or if input utxo requires single sig with smart contract(p2wsh or p2sh)
await tx.signInput(
    pubkey,
    privkey,
    0, // input index to sign
    // below are optional, use to sign legacy utxo or unlock smart contract utxo
    'segwit', // default is segwit, you might use legacy if necessary
    await bitcoin.script.generateTimeLockScript(2542622), // is timelock input? provide script
    'secret', // is hashlock input? provide secret to unlock
);


// or if input utxo requires multi sig with smart contract(p2wsh or p2sh)
await tx.multiSignInput(
    [pubkey1, pubkey2, pubkey3],
    [privkey1, privkey2],
    0, // input index to sign
    // below are optional, use to sign legacy utxo or unlock smart contract utxo
    'segwit', // default is segwit, you might use legacy if necessary
    await bitcoin.script.generateTimeLockScript(2542622), // is timelock input? provide script
    'secret', // is hashlock input? provide secret to unlock
);

// or if input utxo requires unlock hash with smart contract(p2wsh or p2sh)
await tx.unlockHashInput(
    'secret',
    0,
    // below are optional, use to unlock legacy utxo or timlock utxo with hashlock
    'segwit', // default is segwit, you might use legacy if necessary
    await bitcoin.script.generateTimeLockScript(2542622),// is timelock input? provide script
);

// You can broadcast signed tx here: https://blockstream.info/testnet/tx/push
const txToBroadcast: string = await tx.getSignedHex();

```

## Advanced feature
### Custom smart contract
``` javascript

import * as bitcoin from 'bitcoin-sdk-js';

// You can send and spend any smart contract. Below example is classic HTLC
const HTLC = bitcoin.Opcode.OP_IF +
        (await bitcoin.script.generateTimeLockScript(2576085)) +
        (await bitcoin.data.pushData(pubkey1)) + // must specify data to read(if not opcode)
        pubkey1 +
        bitcoin.Opcode.OP_ELSE +
        (await bitcoin.script.generateHashLockScript('abcdef')) +
        (await bitcoin.data.pushData(pubkey2)) + // must specify data to read(if not opcode)
        pubkey2 +
        bitcoin.Opcode.OP_ENDIF +
        bitcoin.Opcode.OP_CHECKSIG
// p2sh address, custom contract address must be p2sh(p2wsh)
const toAddress = await bitcoin.address.generateScriptAddress(HTLC);

// Then, can be spent as an input by signing by scriptSig!
await tx.setLocktime(2576085); // if transaction use timelock input, must set tx locktime bigger than input timelock
// spend by executing OP_IF branch
await tx.signInputByScriptSig(
    // script sig list(order matters!!! bitcoin script is stack-based LIFO)
    [
      await bitcoin.crypto.sign(
        // method to get input message hash to sign
        await tx.getInputHashToSign(
          HTLC, // redeem script as p2sh
          0, // input index
        ),
        privkey1, // signer private key
      ),
      '01', // execute OP_IF(if legacy(not segwit), OP_1 instead of '01') 
    ],
    HTLC, // redeem script as p2sh
    0, // input index
  );
// Or spend by executing OP_ELSE branch
await tx.signInputByScriptSig(
    // script sig list(order matters!!! bitcoin script is stack-based LIFO)
    [
      await bitcoin.crypto.sign(
        // method to get input message hash to sign
        await tx.getInputHashToSign(
          HTLC, // redeem script as p2sh
          0, // input index
        ),
        privkey2, // signer private key
      ),
      'abcdef', // unlock hash
      '', // execute OP_ELSE 
    ],
    HTLC, // redeem script as p2sh
    0, // input index
  );


```


## 📜 License
This software is licensed under the MIT ©.
