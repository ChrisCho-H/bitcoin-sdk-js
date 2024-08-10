## bitcoin-sdk-js

**✨ Bitcoin TypeScript/JavaScript Library for NodeJS, Browser and Mobile ✨**

_Bitcoin is hard. Especially for those not familiar with crypto, it is even hard
to create a simple bitcoin transaction._

bitcoin-sdk-js provides various features which help to **create various type of bitcoin transaction so easily🚀**,
including **advanced smart contract like multisig, hashlock, timelock, combination of them, and even your own smart contract**.

**Legacy, Segwit, Taproot features are all suppoted!**

## Install
``` bash
npm install bitcoin-sdk-js
```
## How To Use
- [Generate Address](#generate-address-p2pkh-p2wpkh-p2sh-p2wsh-p2tr)
  - [Address for Single Signer(P2PKH, P2WPKH, P2TR)](#1-address-for-single-signerp2pkh-p2wpkh-p2tr)
  - [Address for Script(P2SH, P2WSH)](#2-address-for-scriptp2sh-p2wsh)
- [Create Transaction](#create-transaction-p2pkh-p2wpkh-p2sh-p2wsh-p2tr)
  - [Transaction for Single Signer(P2PKH, P2WPKH)](#1-transaction-for-single-signerp2pkh-p2wpkh)
  - [Transaction for Multi Signer(P2SH, P2WSH)](#2-transaction-for-multi-signerp2sh-p2wsh)
  - [Transaction for Single(or Multi) Signer with TimeLock (or || and) HashLock(P2SH, P2WSH)](#3-transaction-for-singleor-multi-signer-with-timelock-or--and-hashlockp2sh-p2wsh)
  - [Transaction for TimeLock (or || and) HashLock without Signer(P2SH, P2WSH)](#4-transaction-for-timelock-or--and-hashlock-without-signerp2sh-p2wsh)
  - [Custom smart contract(P2SH, P2WSH)](#5-custom-smart-contractp2sh-p2wsh)
  - [Taproot and Tapscript spend(P2TR)](#6-taproot-and-tapscript-spendp2tr)
- [Sign Message and Verify Signature - BIP322 (P2PKH, P2WPKH, P2TR)](#sign-message-and-verify-signature---bip322-p2pkh-p2wpkh-p2tr)
### Generate Address (P2PKH, P2WPKH, P2SH, P2WSH, P2TR)
#### 1. Address for Single Signer(P2PKH, P2WPKH, P2TR)
``` javascript

import * as bitcoin from 'bitcoin-sdk-js'

// if you need to generate key pair
const keyPair = await bitcoin.wallet.generateKeyPair();
// p2pkh
const legacyAddress = await bitcoin.address.generateAddress(
  keyPair.publicKey,
  'legacy',
);
// p2wpkh
const segwitAddress = await bitcoin.address.generateAddress(
  keyPair.publicKey,
  'segwit',
);
// p2tr
const taprootAddress = await bitcoin.address.generateAddress(
  (
    // It's recommended to tweak public key to generate taproot address
    await bitcoin.tapscript.getTapTweakedPubkey(
      // Schnorr key is same with any bitcoin key pair, except it does not use public key prefix byte '02' or '03'.
      keyPair.publicKey.slice(2),
      await bitcoin.tapscript.getTapTweak(keyPair.publicKey.slice(2)),
    )
  ).tweakedPubKey,
  'taproot',
);
// p2pkh - testnet
const legacyAddressTestnet = await bitcoin.address.generateAddress(
  keyPair.publicKey,
  'legacy',
  'testnet',
);
// p2wpkh - testnet
const segwitAddressTestnet = await bitcoin.address.generateAddress(
  keyPair.publicKey,
  'segwit',
  'testnet',
);
// p2tr - testnet
const taprootAddressTestnet = await bitcoin.address.generateAddress(
  (
    // It's recommended to tweak public key to generate taproot address
    await bitcoin.tapscript.getTapTweakedPubkey(
      // Schnorr key is same with any bitcoin key pair, except it does not use public key prefix byte '02' or '03'.
      keyPair.publicKey.slice(2),
      await bitcoin.tapscript.getTapTweak(keyPair.publicKey.slice(2)),
    )
  ).tweakedPubKey,
  'taproot',
  'testnet',
);

```
#### 2. Address for Script(P2SH, P2WSH)
``` javascript

import * as bitcoin from 'bitcoin-sdk-js'

// if you need to generate key pair
const keyPair = await bitcoin.wallet.generateKeyPair();
// Script can be any of bitcoin script opcode! bitcoin-sdk-js provides an easy way to build script.
// Below script is timelock + single sig
const script = 
      await bitcoin.script.generateTimeLockScript(2542622) + await bitcoin.script.generateSingleSigScript(keyPair.publicKey);
// p2sh
const legacyScriptAddress = await bitcoin.address.generateScriptAddress(
  script,
  'legacy',
);
// p2wsh
const segwitScriptAddress = await bitcoin.address.generateScriptAddress(
  script,
  'segwit',
);
// p2sh - testnet
const legacyScriptAddressTestnet = await bitcoin.address.generateScriptAddress(
  script,
  'legacy',
  'testnet',
);
// p2wsh - testnet
const segwitScriptAddressTestnet = await bitcoin.address.generateScriptAddress(
  script,
  'segwit',
  'testnet',
);

```
### Create Transaction (P2PKH, P2WPKH, P2SH, P2WSH, P2TR)
#### 1. Transaction for Single Signer(P2PKH, P2WPKH)
``` javascript

import * as bitcoin from 'bitcoin-sdk-js';

// if you need to generate key pair
const keyPair = await bitcoin.wallet.generateKeyPair();
const pubkey = keyPair.publicKey;
const privkey = keyPair.privateKey;

// initialize Bitcoin Transaction object
const tx = new bitcoin.Transaction();

// add UTXO to spend as an input
await tx.addInput({
  txHash: txId, // transaction id of utxo
  index: 0, // index of utxo in transaction
  value: value, // value of utxo(unit is satoshi)
} as bitcoin.UTXO);

// add Target output to send Bitcoin
// most common transaction which sends bitcoin to single sig address
await tx.addOutput({
    address: await bitcoin.address.generateAddress(pubkey),
    value: value - fee, // value of utxo - fee
} as bitcoin.Target);

// if input utxo only requires single sig(p2wpkh or p2pkh)
await tx.signInput(privkey, 0);

// You can broadcast signed tx here: https://blockstream.info/testnet/tx/push
const txToBroadcast: string = await tx.getSignedHex();

```
#### 2. Transaction for Multi Signer(P2SH, P2WSH)
``` javascript

import * as bitcoin from 'bitcoin-sdk-js';

// initialize Bitcoin Transaction object
const tx = new bitcoin.Transaction();

// add UTXO to spend as an input
await tx.addInput({
  txHash: txId, // transaction id of utxo
  index: 0, // index of utxo in transaction
  value: value, // value of utxo(unit is satoshi)
} as bitcoin.UTXO);

// add Target output to send Bitcoin
// sends bitcoin to 2-of-3 multisig transaction
await tx.addOutput({
    // all the smart contract output is recommended to use script address!
    address: await bitcoin.address.generateScriptAddress(
        // this generate multisig smart contract, which is possible up to 15-of-15 
        await bitcoin.script.generateMultiSigScript(2, [pubkey1, pubkey2, pubkey3]),
    ),
    value: value - fee, // value of utxo - fee
} as bitcoin.Target);

// if input utxo requires multi sig(p2wsh or p2sh)
await tx.multiSignInput(
    [pubkey1, pubkey2, pubkey3],
    [privkey1, privkey2],
    0, // input index to sign
);

// You can broadcast signed tx here: https://blockstream.info/testnet/tx/push
const txToBroadcast: string = await tx.getSignedHex();

```

#### 3. Transaction for Single(or Multi) Signer with TimeLock (or || and) HashLock(P2SH, P2WSH)
``` javascript

import * as bitcoin from 'bitcoin-sdk-js';

// initialize Bitcoin Transaction object
const tx = new bitcoin.Transaction();

// add UTXO to spend as an input
await tx.addInput({
  txHash: txId, // transaction id of utxo
  index: 0, // index of utxo in transaction
  value: value, // value of utxo(unit is satoshi)
} as bitcoin.UTXO);

// add Target output to send Bitcoin
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
        // able to spend this output if 'secretHex' is given
        (await bitcoin.script.generateHashLockScript('secretHex')) + 
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
        (await bitcoin.script.generateHashLockScript('secretHex')) +
        // you can use generateMultiSigScript instead of single sig here
        (await bitcoin.script.generateSingleSigScript(pubkey)),
    ),
    value: value - fee, // value of utxo - fee
} as bitcoin.Target);

// if transaction use timelock input, must set tx locktime bigger than input timelock
await tx.setLocktime(2542622);

// if input utxo requires single sig with smart contract(p2wsh or p2sh)
await tx.signInput(
    privkey,
    0, // input index to sign
    'segwit', // default is segwit, you might use legacy if necessary
    await bitcoin.script.generateTimeLockScript(2542622), // is timelock input? provide script
    'secretHex', // is hashlock input? provide secretHex to unlock
);

// or if input utxo requires multi sig with smart contract(p2wsh or p2sh)
await tx.multiSignInput(
    [pubkey1, pubkey2, pubkey3],
    [privkey1, privkey2],
    0, // input index to sign
    'segwit', // default is segwit, you might use legacy if necessary
    await bitcoin.script.generateTimeLockScript(2542622), // is timelock input? provide script
    'secretHex', // is hashlock input? provide secretHex to unlock
);

// You can broadcast signed tx here: https://blockstream.info/testnet/tx/push
const txToBroadcast: string = await tx.getSignedHex();
```
#### 4. Transaction for TimeLock (or || and) HashLock without Signer(P2SH, P2WSH)
``` javascript

import * as bitcoin from 'bitcoin-sdk-js';

// initialize Bitcoin Transaction object
const tx = new bitcoin.Transaction();

// add UTXO to spend as an input
await tx.addInput({
  txHash: txId, // transaction id of utxo
  index: 0, // index of utxo in transaction
  value: value, // value of utxo(unit is satoshi)
} as bitcoin.UTXO);

// add Target output to send Bitcoin
// sends bitcoin to script with timelock + hashlock (no sig required)
await tx.addOutput({
    address: await bitcoin.address.generateScriptAddress(
        // if you only want hashlock, you can remove generateTimeLockScript
        (await bitcoin.script.generateTimeLockScript(2542622)) +
        (await bitcoin.script.generateHashLockScript('secretHex')),   
    ),
    value: value - fee, // value of utxo - fee
} as bitcoin.Target);

// if transaction use timelock input, must set tx locktime bigger than input timelock
await tx.setLocktime(2542622);

// if input utxo requires to unlock hash with smart contract(p2wsh or p2sh)
await tx.unlockHashInput(
    'secretHex',
    0,
    'segwit', // default is segwit, you might use legacy if necessary
    await bitcoin.script.generateTimeLockScript(2542622),// is timelock input? provide script
);

// You can broadcast signed tx here: https://blockstream.info/testnet/tx/push
const txToBroadcast: string = await tx.getSignedHex();

```
#### 5. Custom smart contract(P2SH, P2WSH)
You might use tapscript for this!
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
// p2wsh address, custom contract address must be p2wsh(p2sh) (or taproot address, check next chapter!)
const toAddress = await bitcoin.address.generateScriptAddress(HTLC);

// Then, can be spent as an input by signing by scriptSig!
// initialize Bitcoin Transaction object
const tx = new bitcoin.Transaction();

// if transaction use timelock input, must set tx locktime bigger than input timelock
await tx.setLocktime(2576085); 

// spend by executing OP_IF branch
await tx.signInputByScriptSig(
    // script sig list(order matters!!! bitcoin script is stack-based LIFO)
    [
      await bitcoin.crypto.sign(
        // method to get input message hash to sign
        await tx.getInputHashToSign(
          HTLC, // redeem script as p2wsh
          0, // input index
        ),
        privkey1, // signer private key
      ),
      '01', // execute OP_IF
      HTLC, // redeem script as p2wsh
    ],
    0, // input index
  );
// Or spend by executing OP_ELSE branch
await tx.signInputByScriptSig(
    // script sig list(order matters!!! bitcoin script is stack-based LIFO)
    [
      await bitcoin.crypto.sign(
        // method to get input message hash to sign
        await tx.getInputHashToSign(
          HTLC, // redeem script as p2wsh
          0, // input index
        ),
        privkey2, // signer private key
      ),
      'abcdef', // unlock hash
      '', // execute OP_ELSE
      HTLC, // redeem script as p2sh
    ],
    0, // input index
  );

// You can broadcast signed tx here: https://blockstream.info/testnet/tx/push
const txToBroadcast: string = await tx.getSignedHex();

```

#### 6. Taproot and Tapscript spend(P2TR)
``` javascript


import * as bitcoin from 'bitcoin-sdk-js';

// Let's send and spend above HTLC in taproot and tapscript way!
/*
  Schnorr key is same with any bitcoin key pair, except it does not use public key prefix byte '02' or '03'.
  This key pair will be used as a master key to spend UTXO in taproot, after tweaked(will explain how to step by step).
*/
const keyPair = await bitcoin.wallet.generateKeyPair();
const schnorrPubkey = keyPair.publicKey.slice(2); // remove first byte (which is parity bit)
const schnorrPrivkey = keyPair.privateKey;

/*
  HTLC consists of conditional branch, in which OP_IF contains Time Lock Contract and OP_ELSE contains Hash Lock.
  We can construct tapscript tree where each leaf has its own contract(script), enable unlimited spending branches.
*/
// Originally OP_IF branch Time Lock Contract
const timeLockContract =
    (await bitcoin.script.generateTimeLockScript(2576085)) +
    (await bitcoin.data.pushData(schnorrPubkey1)) + // must specify data to read(if not opcode)
    schnorrPubkey1 + // you must use schnorr key even in tapscript
    bitcoin.Opcode.OP_CHECKSIG;
// Originally OP_ELSE branch Hash Lock Contract
const hashLockContract =
    (await bitcoin.script.generateHashLockScript('abcdef')) +
    (await bitcoin.data.pushData(schnorrPubkey2)) + // must specify data to read(if not opcode)
    schnorrPubkey2 + // you must use schnorr key even in tapscript
    bitcoin.Opcode.OP_CHECKSIG;

/*
  You can get tapbranch from a pair of script, and repeat over to reach to the root of tree(which is 'taproot') 
  Here we have only a single pair of script, so tapbranch of it is taproot
*/
const taproot = await bitcoin.tapscript.getTapBranch([
    await bitcoin.tapscript.getTapLeaf(timeLockContract),
    await bitcoin.tapscript.getTapLeaf(hashLockContract),
]);
// Then, get taptweak with schnorr key generated above
const tapTweak = await bitcoin.tapscript.getTapTweak(
    schnorrPubkey,
    taproot,
);
// Finally, you can tweak schnorr public key, which can be used as taproot key!
const tapTweakedPubkey = await bitcoin.tapscript.getTapTweakedPubkey(
    schnorrPubkey,
    tapTweak,
);
// generate taproot address with taproot key(and send to it!)
const toAddress = await bitcoin.address.generateAddress(tapTweakedPubkey.tweakedPubKey, 'taproot');

// initialize Bitcoin Transaction object
const tx = new bitcoin.Transaction();

await tx.setLocktime(2576085); // if transaction use timelock input, must set tx locktime bigger than input timelock

// Then, can be spent as an input!
// one thing to keep in mind, taproot or tapscript spend needs to provide all the script public key of input
await tx.addInput({
    txHash: txId,
    index: 0,
    value: value,
    script: await bitcoin.script.getScriptByAddress(toAddress),
});

// taproot spend? just sign input with tweaked schnorr key(which is, taproot private key)
await tx.signInput(
    await bitcoin.tapscript.getTapTweakedPrivkey(schnorrPrivkey, tapTweak), // provide tweaked private key
    0,
    'taproot',
);

// Or tapscript spend? Let's spend by hash lock script!
const sigStack = [
    await bitcoin.crypto.sign(
      await tx.getInputHashToSign(hashLockContract, 0, 'tapscript'),
      schnorrPrivkey2,
      'schnorr',
    ), // schnorr signature
    'abcdef', // hash to unlock
    hashLockContract, // spend script
    // you must specify path to find taproot with provided script(For more detail, check BIP341!)
    await bitcoin.tapscript.getTapControlBlock(
      schnorrPubkey,
      tapTweakedPubkey.parityBit,
      await bitcoin.tapscript.getTapLeaf(timeLockContract), // path to find taproot
    ),
];

await tx.signInputByScriptSig(sigStack, 0, 'tapscript');

// You can broadcast signed tx here: https://blockstream.info/testnet/tx/push
const txToBroadcast: string = await tx.getSignedHex();

```

### Sign Message and Verify Signature - BIP322 (P2PKH, P2WPKH, P2TR)

``` javascript

import * as bitcoin from 'bitcoin-sdk-js'

// if you need to generate key pair
const keyPair = await bitcoin.wallet.generateKeyPair();
const pubkey = keyPair.publicKey;
const privkey = keyPair.privateKey;

// address to verify(legacy p2pkh, segwit p2wpkh, taproot p2tr are all supported!)
const legacyAddress = await bitcoin.address.generateAddress(
  pubkey,
  'legacy',
);
const segwitAddress = await bitcoin.address.generateAddress(
  pubkey,
  'segwit',
);
const tapAddress = await bitcoin.address.generateAddress(
  (
    await bitcoin.tapscript.getTapTweakedPubkey(
      pubkey.slice(2),
      await bitcoin.tapscript.getTapTweak(pubkey.slice(2)),
    )
  ).tweakedPubKey,
  'taproot',
);
// message to sign
const msg = "message to sign";
// sign messsage with private key and address
const sigLegacy = await bitcoin.crypto.signMessage(
  msg,
  privkey,
  legacyAddress,
);
const sigSegwit = await bitcoin.crypto.signMessage(
  msg,
  privkey,
  segwitAddress,
);
const sigTap = await bitcoin.crypto.signMessage(msg, privkey, tapAddress);
// verify signature from address, returning boolean.
await bitcoin.crypto.verifyMessage(msg, sigLegacy, legacyAddress);
await bitcoin.crypto.verifyMessage(msg, sigSegwit, segwitAddress);
await bitcoin.crypto.verifyMessage(msg, sigTap, tapAddress);

```



## 📜 License
This software is licensed under the MIT ©.
