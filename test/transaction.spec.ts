// tx
import * as assert from 'assert';
import { describe, it } from 'mocha';
import * as bitcoin from '../src/index.js';

describe('legacy transaction test', () => {
  it('sign, multi-sign, timelock and hashlock spent', async () => {
    // Given
    const version: number = 1;
    const inputCount = 5;
    const txHash: string = await bitcoin.encode.bytesToHex(
      crypto.getRandomValues(new Uint8Array(32)),
    );
    const index: number = Math.floor(
      Math.random() * (0xffffffff - inputCount - 0 + 1) + 0,
    );
    const value: number = Math.random() * (Number.MAX_SAFE_INTEGER - 0 + 1) + 0;
    const keypair: bitcoin.wallet.KeyPair =
      await bitcoin.wallet.generateKeyPair();
    const locktime: number = Math.floor(
      Math.random() * (500000000 - 1 - 0 + 1) + 0,
    );
    const secretHex: string = await bitcoin.encode.bytesToHex(
      crypto.getRandomValues(new Uint8Array(32)),
    );
    const HTLC: string =
      bitcoin.Opcode.OP_IF +
      (await bitcoin.script.generateTimeLockScript(locktime)) +
      (await bitcoin.data.pushData(keypair.publicKey)) +
      keypair.publicKey +
      bitcoin.Opcode.OP_ELSE +
      (await bitcoin.script.generateHashLockScript(secretHex)) +
      (await bitcoin.data.pushData(keypair.publicKey)) +
      keypair.publicKey +
      bitcoin.Opcode.OP_ENDIF +
      bitcoin.Opcode.OP_CHECKSIG;

    // When
    const tx = new bitcoin.Transaction();
    await tx.setVersion(version);
    await tx.setLocktime(locktime);
    for (let i = 0; i < inputCount; i++)
      await tx.addInput({
        txHash: txHash,
        index: index + i,
        value: value,
      });
    // simple p2pkh address
    await tx.addOutput({
      address: await bitcoin.address.generateAddress(
        keypair.publicKey,
        'legacy',
      ),
      value: value,
    });
    // 2-of-4 multisig
    await tx.addOutput({
      address: await bitcoin.address.generateScriptAddress(
        await bitcoin.script.generateMultiSigScript(2, [
          keypair.publicKey,
          keypair.publicKey,
          keypair.publicKey,
          keypair.publicKey,
        ]),
        'legacy',
      ),
      value: value,
    });
    // hash time lock without sig verification
    await tx.addOutput({
      address: await bitcoin.address.generateScriptAddress(
        (await bitcoin.script.generateTimeLockScript(locktime)) +
          (await bitcoin.script.generateHashLockScript(secretHex)),
        'legacy',
      ),
      value: value,
    });
    // timelock + multisig 1-of-3
    await tx.addOutput({
      address: await bitcoin.address.generateScriptAddress(
        (await bitcoin.script.generateTimeLockScript(locktime)) +
          (await bitcoin.script.generateMultiSigScript(1, [
            keypair.publicKey,
            keypair.publicKey,
            keypair.publicKey,
          ])),
        'legacy',
      ),
      value: value,
    });
    // custom smart contract
    await tx.addOutput({
      address: await bitcoin.address.generateScriptAddress(HTLC, 'legacy'),
      value: value,
    });
    // sign input
    await tx.signInput(keypair.privateKey, 0, 'legacy');
    await tx.multiSignInput(
      [
        keypair.publicKey,
        keypair.publicKey,
        keypair.publicKey,
        keypair.publicKey,
      ],
      [keypair.privateKey, keypair.privateKey],
      1,
      'legacy',
    );
    await tx.signInput(
      keypair.privateKey,
      2,
      'legacy',
      await bitcoin.script.generateTimeLockScript(locktime),
      secretHex,
    );
    await tx.multiSignInput(
      [
        keypair.publicKey,
        keypair.publicKey,
        keypair.publicKey,
        keypair.publicKey,
      ],
      [keypair.privateKey, keypair.privateKey],
      3,
      'legacy',
      await bitcoin.script.generateTimeLockScript(locktime),
      secretHex,
    );
    await tx.signInputByScriptSig(
      [
        await bitcoin.crypto.sign(
          await tx.getInputHashToSign(HTLC, 4, 'legacy'),
          keypair.privateKey,
        ),
        secretHex,
        '',
        HTLC,
      ],
      4,
      'legacy',
    );

    const txHex = await tx.getSignedHex();

    // Then
    // check transaction version
    let interpreterIndex = 0;
    assert.strictEqual(
      Number(
        '0x' +
          (await bitcoin.encode.reverseHex(
            txHex.slice(interpreterIndex, (interpreterIndex += 8)),
          )),
      ),
      version,
    );
    // check transaction input count
    const inputCountVarInt: string = await bitcoin.data.getVarInt(inputCount);
    assert.strictEqual(
      inputCountVarInt,
      txHex.slice(
        interpreterIndex,
        (interpreterIndex += inputCountVarInt.length),
      ),
    );
    // check transaction input tx hash
    assert.strictEqual(
      await bitcoin.encode.reverseHex(txHash),
      txHex.slice(interpreterIndex, (interpreterIndex += 64)),
    );
    // check transaction input index
    assert.strictEqual(
      index,
      Number(
        '0x' +
          (await bitcoin.encode.reverseHex(
            txHex.slice(interpreterIndex, (interpreterIndex += 8)),
          )),
      ),
    );

    // 1. validate p2pkh script sig
    // varint is a single byte for p2pkh
    const currentInterpreterIndexSingleSig = interpreterIndex;
    const singleSigScriptSigVarInt: number = await bitcoin.data.varIntToNumber(
      txHex.slice(interpreterIndex, (interpreterIndex += 2)),
    );
    // signature bytes to read is a single byte
    const sigBytesToRead: number = await bitcoin.data.pushDataToNumber(
      txHex.slice(interpreterIndex, (interpreterIndex += 2)),
    );
    assert.strictEqual(
      true,
      await bitcoin.crypto.verify(
        txHex.slice(interpreterIndex, (interpreterIndex += sigBytesToRead * 2)),
        await tx.getInputHashToSign(
          await bitcoin.script.generateSingleSigScript(keypair.publicKey),
          0,
          'legacy',
        ),
        // pubkey bytes to read is a single byte
        txHex.slice((interpreterIndex += 2), (interpreterIndex += 66)),
      ),
    );
    // check varint of script sig
    assert.strictEqual(
      interpreterIndex,
      // varint itself is a single bytes
      currentInterpreterIndexSingleSig + 2 + singleSigScriptSigVarInt * 2,
    );
    // check input sequence and varint of script sig, default to fdffffff
    assert.strictEqual(
      txHex.slice(interpreterIndex, (interpreterIndex += 8)),
      'fdffffff',
    );

    // 2. validate p2sh multisig script sig
    // check transaction input tx hash
    assert.strictEqual(
      await bitcoin.encode.reverseHex(txHash),
      txHex.slice(interpreterIndex, (interpreterIndex += 64)),
    );
    // check transaction input index
    assert.strictEqual(
      index + 1,
      Number(
        '0x' +
          (await bitcoin.encode.reverseHex(
            txHex.slice(interpreterIndex, (interpreterIndex += 8)),
          )),
      ),
    );
    // varint is two byte for 2-of-4 multisig
    const currentInterpreterIndexMultiSig = interpreterIndex;
    const multiSigScriptSigVarInt: number = await bitcoin.data.varIntToNumber(
      txHex.slice(interpreterIndex, (interpreterIndex += 6)),
    );
    // OP_0 for multisig
    assert.strictEqual(
      bitcoin.Opcode.OP_0,
      txHex.slice(interpreterIndex, (interpreterIndex += 2)),
    );
    // first signature bytes to read is a single byte
    const firstSigBytesToRead: number = await bitcoin.data.pushDataToNumber(
      txHex.slice(interpreterIndex, (interpreterIndex += 2)),
    );
    assert.strictEqual(
      true,
      await bitcoin.crypto.verify(
        txHex.slice(
          interpreterIndex,
          (interpreterIndex += firstSigBytesToRead * 2),
        ),
        await tx.getInputHashToSign(
          await bitcoin.script.generateMultiSigScript(2, [
            keypair.publicKey,
            keypair.publicKey,
            keypair.publicKey,
            keypair.publicKey,
          ]),
          1,
          'legacy',
        ),
        // pubkey bytes to read is a single byte
        keypair.publicKey,
      ),
    );
    // second signature bytes to read is a single byte
    const secondSigBytesToRead: number = await bitcoin.data.pushDataToNumber(
      txHex.slice(interpreterIndex, (interpreterIndex += 2)),
    );
    assert.strictEqual(
      true,
      await bitcoin.crypto.verify(
        txHex.slice(
          interpreterIndex,
          (interpreterIndex += secondSigBytesToRead * 2),
        ),
        await tx.getInputHashToSign(
          await bitcoin.script.generateMultiSigScript(2, [
            keypair.publicKey,
            keypair.publicKey,
            keypair.publicKey,
            keypair.publicKey,
          ]),
          1,
          'legacy',
        ),
        // pubkey bytes to read is a single byte
        keypair.publicKey,
      ),
    );
    // redeem script check(2-of-4 multisig redeem script longer than 76 bytes)
    const redeemScriptBytesToRead: number = await bitcoin.data.pushDataToNumber(
      txHex.slice(interpreterIndex, (interpreterIndex += 4)),
    );
    assert.strictEqual(
      await bitcoin.script.generateMultiSigScript(2, [
        keypair.publicKey,
        keypair.publicKey,
        keypair.publicKey,
        keypair.publicKey,
      ]),
      txHex.slice(
        interpreterIndex,
        (interpreterIndex += redeemScriptBytesToRead * 2),
      ),
    );
    // check varint of script sig
    assert.strictEqual(
      interpreterIndex,
      // varint itself is 3 bytes
      currentInterpreterIndexMultiSig + 6 + multiSigScriptSigVarInt * 2,
    );
    // check input sequence and varint of script sig, default to fdffffff
    assert.strictEqual(
      txHex.slice(interpreterIndex, (interpreterIndex += 8)),
      'fdffffff',
    );

    // 3. validate p2sh single sig htlc script sig
    // check transaction input tx hash
    assert.strictEqual(
      await bitcoin.encode.reverseHex(txHash),
      txHex.slice(interpreterIndex, (interpreterIndex += 64)),
    );
    // check transaction input index
    assert.strictEqual(
      index + 2,
      Number(
        '0x' +
          (await bitcoin.encode.reverseHex(
            txHex.slice(interpreterIndex, (interpreterIndex += 8)),
          )),
      ),
    );
    // varint is a single byte for single sig htlc script sig
    const currentInterpreterIndexSingleSigHTLC = interpreterIndex;
    const singleSigHTLCScriptSigVarInt: number =
      await bitcoin.data.varIntToNumber(
        txHex.slice(interpreterIndex, (interpreterIndex += 2)),
      );
    // first signature bytes to read is a single byte
    const htlcSigBytesToRead: number = await bitcoin.data.pushDataToNumber(
      txHex.slice(interpreterIndex, (interpreterIndex += 2)),
    );
    assert.strictEqual(
      true,
      await bitcoin.crypto.verify(
        txHex.slice(
          interpreterIndex,
          (interpreterIndex += htlcSigBytesToRead * 2),
        ),
        await tx.getInputHashToSign(
          (await bitcoin.script.generateTimeLockScript(locktime)) +
            (await bitcoin.script.generateHashLockScript(secretHex)) +
            (await bitcoin.script.generateSingleSigScript(keypair.publicKey)),
          2,
          'legacy',
        ),
        // pubkey bytes to read is a single byte
        txHex.slice((interpreterIndex += 2), (interpreterIndex += 66)),
      ),
    );
    // secret hex bytes to read is a single byte
    const htlcSecretBytesToRead: number = await bitcoin.data.pushDataToNumber(
      txHex.slice(interpreterIndex, (interpreterIndex += 2)),
    );
    assert.strictEqual(
      secretHex,
      txHex.slice(
        interpreterIndex,
        (interpreterIndex += htlcSecretBytesToRead * 2),
      ),
    );
    // redeem script check
    const htlcRedeemScriptBytesToRead: number =
      await bitcoin.data.pushDataToNumber(
        txHex.slice(interpreterIndex, (interpreterIndex += 2)),
      );
    assert.strictEqual(
      (await bitcoin.script.generateTimeLockScript(locktime)) +
        (await bitcoin.script.generateHashLockScript(secretHex)) +
        (await bitcoin.script.generateSingleSigScript(keypair.publicKey)),
      txHex.slice(
        interpreterIndex,
        (interpreterIndex += htlcRedeemScriptBytesToRead * 2),
      ),
    );
    // check varint of script sig
    assert.strictEqual(
      interpreterIndex,
      // varint itself is a single bytes
      currentInterpreterIndexSingleSigHTLC +
        2 +
        singleSigHTLCScriptSigVarInt * 2,
    );
    // check input sequence and varint of script sig, default to fdffffff
    assert.strictEqual(
      txHex.slice(interpreterIndex, (interpreterIndex += 8)),
      'fdffffff',
    );

    // 4. validate p2sh htlc multisig script sig
    // check transaction input tx hash
    assert.strictEqual(
      await bitcoin.encode.reverseHex(txHash),
      txHex.slice(interpreterIndex, (interpreterIndex += 64)),
    );
    // check transaction input index
    assert.strictEqual(
      index + 3,
      Number(
        '0x' +
          (await bitcoin.encode.reverseHex(
            txHex.slice(interpreterIndex, (interpreterIndex += 8)),
          )),
      ),
    );
    // varint is two byte for 2-of-4 multisig htlc
    const currentInterpreterIndexMultiSigHtlc = interpreterIndex;
    const htlcMultiSigScriptSigVarInt: number =
      await bitcoin.data.varIntToNumber(
        txHex.slice(interpreterIndex, (interpreterIndex += 6)),
      );
    // OP_0 for multisig
    assert.strictEqual(
      bitcoin.Opcode.OP_0,
      txHex.slice(interpreterIndex, (interpreterIndex += 2)),
    );
    // first signature bytes to read is a single byte
    const firstHtlcSigBytesToRead: number = await bitcoin.data.pushDataToNumber(
      txHex.slice(interpreterIndex, (interpreterIndex += 2)),
    );
    assert.strictEqual(
      true,
      await bitcoin.crypto.verify(
        txHex.slice(
          interpreterIndex,
          (interpreterIndex += firstHtlcSigBytesToRead * 2),
        ),
        await tx.getInputHashToSign(
          (await bitcoin.script.generateTimeLockScript(locktime)) +
            (await bitcoin.script.generateHashLockScript(secretHex)) +
            (await bitcoin.script.generateMultiSigScript(2, [
              keypair.publicKey,
              keypair.publicKey,
              keypair.publicKey,
              keypair.publicKey,
            ])),
          3,
          'legacy',
        ),
        // pubkey bytes to read is a single byte
        keypair.publicKey,
      ),
    );
    // second signature bytes to read is a single byte
    const secondHtlcSigBytesToRead: number =
      await bitcoin.data.pushDataToNumber(
        txHex.slice(interpreterIndex, (interpreterIndex += 2)),
      );
    assert.strictEqual(
      true,
      await bitcoin.crypto.verify(
        txHex.slice(
          interpreterIndex,
          (interpreterIndex += secondHtlcSigBytesToRead * 2),
        ),
        await tx.getInputHashToSign(
          (await bitcoin.script.generateTimeLockScript(locktime)) +
            (await bitcoin.script.generateHashLockScript(secretHex)) +
            (await bitcoin.script.generateMultiSigScript(2, [
              keypair.publicKey,
              keypair.publicKey,
              keypair.publicKey,
              keypair.publicKey,
            ])),
          3,
          'legacy',
        ),
        // pubkey bytes to read is a single byte
        keypair.publicKey,
      ),
    );
    // secret hex bytes to read is a single byte
    const htlcMultiSigSecretBytesToRead: number =
      await bitcoin.data.pushDataToNumber(
        txHex.slice(interpreterIndex, (interpreterIndex += 2)),
      );
    assert.strictEqual(
      secretHex,
      txHex.slice(
        interpreterIndex,
        (interpreterIndex += htlcMultiSigSecretBytesToRead * 2),
      ),
    );
    // redeem script check(2-of-4 multisig htlc redeem script longer than 76 bytes)
    const htlcMultiSigRedeemScriptBytesToRead: number =
      await bitcoin.data.pushDataToNumber(
        txHex.slice(interpreterIndex, (interpreterIndex += 4)),
      );
    assert.strictEqual(
      (await bitcoin.script.generateTimeLockScript(locktime)) +
        (await bitcoin.script.generateHashLockScript(secretHex)) +
        (await bitcoin.script.generateMultiSigScript(2, [
          keypair.publicKey,
          keypair.publicKey,
          keypair.publicKey,
          keypair.publicKey,
        ])),
      txHex.slice(
        interpreterIndex,
        (interpreterIndex += htlcMultiSigRedeemScriptBytesToRead * 2),
      ),
    );
    // check varint of script sig
    assert.strictEqual(
      interpreterIndex,
      // varint itself is 3 bytes
      currentInterpreterIndexMultiSigHtlc + 6 + htlcMultiSigScriptSigVarInt * 2,
    );
    // check input sequence and varint of script sig, default to fdffffff
    assert.strictEqual(
      txHex.slice(interpreterIndex, (interpreterIndex += 8)),
      'fdffffff',
    );

    // 5. validate p2sh custom smart contract signing with
    // check transaction input tx hash
    assert.strictEqual(
      await bitcoin.encode.reverseHex(txHash),
      txHex.slice(interpreterIndex, (interpreterIndex += 64)),
    );
    // check transaction input index
    assert.strictEqual(
      index + 4,
      Number(
        '0x' +
          (await bitcoin.encode.reverseHex(
            txHex.slice(interpreterIndex, (interpreterIndex += 8)),
          )),
      ),
    );
    // varint is a single byte for HTLC
    const currentInterpreterIndexHtlc = interpreterIndex;
    const customHtlcScriptSigVarInt: number = await bitcoin.data.varIntToNumber(
      txHex.slice(interpreterIndex, (interpreterIndex += 2)),
    );
    // signature bytes to read is a single byte
    const customHtlcSigBytesToRead: number =
      await bitcoin.data.pushDataToNumber(
        txHex.slice(interpreterIndex, (interpreterIndex += 2)),
      );
    assert.strictEqual(
      true,
      await bitcoin.crypto.verify(
        txHex.slice(
          interpreterIndex,
          (interpreterIndex += customHtlcSigBytesToRead * 2),
        ),
        await tx.getInputHashToSign(HTLC, 4, 'legacy'),
        // pubkey bytes to read is a single byte
        keypair.publicKey,
      ),
    );
    // second signature bytes to read is a single byte
    const customHtlcSecretBytesToRead: number =
      await bitcoin.data.pushDataToNumber(
        txHex.slice(interpreterIndex, (interpreterIndex += 2)),
      );
    assert.strictEqual(
      secretHex,
      txHex.slice(
        interpreterIndex,
        (interpreterIndex += customHtlcSecretBytesToRead * 2),
      ),
    );
    // empty bytes to execute OP_ELSE
    assert.strictEqual(
      bitcoin.Opcode.OP_0,
      txHex.slice(interpreterIndex, (interpreterIndex += 2)),
    );
    // redeem script check(custom htlc redeem script longer than 76 bytes)
    const customHtlcRedeemScriptBytesToRead: number =
      await bitcoin.data.pushDataToNumber(
        txHex.slice(interpreterIndex, (interpreterIndex += 4)),
      );
    assert.strictEqual(
      HTLC,
      txHex.slice(
        interpreterIndex,
        (interpreterIndex += customHtlcRedeemScriptBytesToRead * 2),
      ),
    );
    // check varint of script sig
    assert.strictEqual(
      interpreterIndex,
      // varint itself is a single bytes
      currentInterpreterIndexHtlc + 2 + customHtlcScriptSigVarInt * 2,
    );
    // check input sequence and varint of script sig, default to fdffffff
    assert.strictEqual(
      txHex.slice(interpreterIndex, (interpreterIndex += 8)),
      'fdffffff',
    );

    // check transaction locktime
    assert.strictEqual(
      Number('0x' + (await bitcoin.encode.reverseHex(txHex.slice(-8)))),
      locktime,
    );
  });
});

describe('segwit transaction test', () => {
  it('sign, multi-sign, timelock and hashlock spent', async () => {
    // Given
    const version: number = 1;
    const inputCount = 5;
    const txHash: string = await bitcoin.encode.bytesToHex(
      crypto.getRandomValues(new Uint8Array(32)),
    );
    const index: number = Math.floor(
      Math.random() * (0xffffffff - inputCount - 0 + 1) + 0,
    );
    const value: number = Math.random() * (Number.MAX_SAFE_INTEGER - 0 + 1) + 0;
    const keypair: bitcoin.wallet.KeyPair =
      await bitcoin.wallet.generateKeyPair();
    const locktime: number = Math.floor(
      Math.random() * (500000000 - 1 - 0 + 1) + 0,
    );
    const secretHex: string = await bitcoin.encode.bytesToHex(
      crypto.getRandomValues(new Uint8Array(32)),
    );
    const HTLC: string =
      bitcoin.Opcode.OP_IF +
      (await bitcoin.script.generateTimeLockScript(locktime)) +
      (await bitcoin.data.pushData(keypair.publicKey)) +
      keypair.publicKey +
      bitcoin.Opcode.OP_ELSE +
      (await bitcoin.script.generateHashLockScript(secretHex)) +
      (await bitcoin.data.pushData(keypair.publicKey)) +
      keypair.publicKey +
      bitcoin.Opcode.OP_ENDIF +
      bitcoin.Opcode.OP_CHECKSIG;

    // When
    const tx = new bitcoin.Transaction();
    await tx.setVersion(version);
    await tx.setLocktime(locktime);
    for (let i = 0; i < inputCount; i++)
      await tx.addInput({
        txHash: txHash,
        index: index + i,
        value: value,
      });
    // simple p2pkh address
    await tx.addOutput({
      address: await bitcoin.address.generateAddress(
        keypair.publicKey,
        'segwit',
      ),
      value: value,
    });
    // 2-of-4 multisig
    await tx.addOutput({
      address: await bitcoin.address.generateScriptAddress(
        await bitcoin.script.generateMultiSigScript(2, [
          keypair.publicKey,
          keypair.publicKey,
          keypair.publicKey,
          keypair.publicKey,
        ]),
        'segwit',
      ),
      value: value,
    });
    // hash time lock without sig verification
    await tx.addOutput({
      address: await bitcoin.address.generateScriptAddress(
        (await bitcoin.script.generateTimeLockScript(locktime)) +
          (await bitcoin.script.generateHashLockScript(secretHex)),
        'segwit',
      ),
      value: value,
    });
    // timelock + multisig 1-of-3
    await tx.addOutput({
      address: await bitcoin.address.generateScriptAddress(
        (await bitcoin.script.generateTimeLockScript(locktime)) +
          (await bitcoin.script.generateMultiSigScript(1, [
            keypair.publicKey,
            keypair.publicKey,
            keypair.publicKey,
          ])),
        'segwit',
      ),
      value: value,
    });
    // custom smart contract
    await tx.addOutput({
      address: await bitcoin.address.generateScriptAddress(HTLC, 'segwit'),
      value: value,
    });
    // to get witness start index!
    await tx.finalize();
    // legacy hex - locktime + segwit flag + segwit marker
    let witnessStartIndex = (await tx.getSignedHex()).length - 8 + 4;
    // sign input
    await tx.signInput(keypair.privateKey, 0, 'segwit');
    await tx.multiSignInput(
      [
        keypair.publicKey,
        keypair.publicKey,
        keypair.publicKey,
        keypair.publicKey,
      ],
      [keypair.privateKey, keypair.privateKey],
      1,
      'segwit',
    );
    await tx.signInput(
      keypair.privateKey,
      2,
      'segwit',
      await bitcoin.script.generateTimeLockScript(locktime),
      secretHex,
    );
    await tx.multiSignInput(
      [
        keypair.publicKey,
        keypair.publicKey,
        keypair.publicKey,
        keypair.publicKey,
      ],
      [keypair.privateKey, keypair.privateKey],
      3,
      'segwit',
      await bitcoin.script.generateTimeLockScript(locktime),
      secretHex,
    );
    await tx.signInputByScriptSig(
      [
        await bitcoin.crypto.sign(
          await tx.getInputHashToSign(HTLC, 4, 'segwit'),
          keypair.privateKey,
        ),
        secretHex,
        '',
        HTLC,
      ],
      4,
      'segwit',
    );

    const txHex = await tx.getSignedHex();

    // Then
    // check transaction version
    let interpreterIndex = 0;
    assert.strictEqual(
      Number(
        '0x' +
          (await bitcoin.encode.reverseHex(
            txHex.slice(interpreterIndex, (interpreterIndex += 8)),
          )),
      ),
      version,
    );
    // check transaction segwitMarker
    assert.strictEqual(
      '00',
      txHex.slice(interpreterIndex, (interpreterIndex += 2)),
    );
    // check transaction segwitFlag
    assert.strictEqual(
      '01',
      txHex.slice(interpreterIndex, (interpreterIndex += 2)),
    );

    // check transaction input count
    const inputCountVarInt: string = await bitcoin.data.getVarInt(inputCount);
    assert.strictEqual(
      inputCountVarInt,
      txHex.slice(
        interpreterIndex,
        (interpreterIndex += inputCountVarInt.length),
      ),
    );
    // check transaction input tx hash
    assert.strictEqual(
      await bitcoin.encode.reverseHex(txHash),
      txHex.slice(interpreterIndex, (interpreterIndex += 64)),
    );
    // check transaction input index
    assert.strictEqual(
      index,
      Number(
        '0x' +
          (await bitcoin.encode.reverseHex(
            txHex.slice(interpreterIndex, (interpreterIndex += 8)),
          )),
      ),
    );

    // 1. validate p2wpkh script sig
    // p2wpkh contains 2 witness items
    const singleSigWitnessItemCount: number = await bitcoin.data.varIntToNumber(
      txHex.slice(witnessStartIndex, (witnessStartIndex += 2)),
    );
    assert.strictEqual(2, singleSigWitnessItemCount);
    // signature bytes to read is a single byte
    const sigBytesToRead: number = await bitcoin.data.varIntToNumber(
      txHex.slice(witnessStartIndex, (witnessStartIndex += 2)),
    );
    assert.strictEqual(
      true,
      await bitcoin.crypto.verify(
        txHex.slice(
          witnessStartIndex,
          (witnessStartIndex += sigBytesToRead * 2),
        ),
        await tx.getInputHashToSign(
          await bitcoin.script.generateSingleSigScript(keypair.publicKey),
          0,
          'segwit',
        ),
        // pubkey bytes to read is a single byte
        txHex.slice((witnessStartIndex += 2), (witnessStartIndex += 66)),
      ),
    );
    // check empty script sig as segwit
    assert.strictEqual(
      txHex.slice(interpreterIndex, (interpreterIndex += 2)),
      bitcoin.Opcode.OP_0,
    );
    // check input sequence and varint of script sig, default to fdffffff
    assert.strictEqual(
      txHex.slice(interpreterIndex, (interpreterIndex += 8)),
      'fdffffff',
    );

    // 2. validate p2wsh multisig script sig
    // check transaction input tx hash
    assert.strictEqual(
      await bitcoin.encode.reverseHex(txHash),
      txHex.slice(interpreterIndex, (interpreterIndex += 64)),
    );
    // check transaction input index
    assert.strictEqual(
      index + 1,
      Number(
        '0x' +
          (await bitcoin.encode.reverseHex(
            txHex.slice(interpreterIndex, (interpreterIndex += 8)),
          )),
      ),
    );
    // p2wsh multisig contains 4 witness items
    const multiSigWitnessItemCount: number = await bitcoin.data.varIntToNumber(
      txHex.slice(witnessStartIndex, (witnessStartIndex += 2)),
    );
    assert.strictEqual(4, multiSigWitnessItemCount);
    // OP_0 for multisig
    assert.strictEqual(
      bitcoin.Opcode.OP_0,
      txHex.slice(witnessStartIndex, (witnessStartIndex += 2)),
    );
    // first signature bytes to read is a single byte
    const firstSigBytesToRead: number = await bitcoin.data.varIntToNumber(
      txHex.slice(witnessStartIndex, (witnessStartIndex += 2)),
    );
    assert.strictEqual(
      true,
      await bitcoin.crypto.verify(
        txHex.slice(
          witnessStartIndex,
          (witnessStartIndex += firstSigBytesToRead * 2),
        ),
        await tx.getInputHashToSign(
          await bitcoin.script.generateMultiSigScript(2, [
            keypair.publicKey,
            keypair.publicKey,
            keypair.publicKey,
            keypair.publicKey,
          ]),
          1,
          'segwit',
        ),
        // pubkey bytes to read is a single byte
        keypair.publicKey,
      ),
    );
    // second signature bytes to read is a single byte
    const secondSigBytesToRead: number = await bitcoin.data.varIntToNumber(
      txHex.slice(witnessStartIndex, (witnessStartIndex += 2)),
    );
    assert.strictEqual(
      true,
      await bitcoin.crypto.verify(
        txHex.slice(
          witnessStartIndex,
          (witnessStartIndex += secondSigBytesToRead * 2),
        ),
        await tx.getInputHashToSign(
          await bitcoin.script.generateMultiSigScript(2, [
            keypair.publicKey,
            keypair.publicKey,
            keypair.publicKey,
            keypair.publicKey,
          ]),
          1,
          'segwit',
        ),
        // pubkey bytes to read is a single byte
        keypair.publicKey,
      ),
    );
    // redeem script check
    const redeemScriptBytesToRead: number = await bitcoin.data.varIntToNumber(
      txHex.slice(witnessStartIndex, (witnessStartIndex += 2)),
    );
    assert.strictEqual(
      await bitcoin.script.generateMultiSigScript(2, [
        keypair.publicKey,
        keypair.publicKey,
        keypair.publicKey,
        keypair.publicKey,
      ]),
      txHex.slice(
        witnessStartIndex,
        (witnessStartIndex += redeemScriptBytesToRead * 2),
      ),
    );
    // check empty script sig as segwit
    assert.strictEqual(
      txHex.slice(interpreterIndex, (interpreterIndex += 2)),
      bitcoin.Opcode.OP_0,
    );
    // check input sequence and varint of script sig, default to fdffffff
    assert.strictEqual(
      txHex.slice(interpreterIndex, (interpreterIndex += 8)),
      'fdffffff',
    );

    // 3. validate p2sh single sig htlc script sig
    // check transaction input tx hash
    assert.strictEqual(
      await bitcoin.encode.reverseHex(txHash),
      txHex.slice(interpreterIndex, (interpreterIndex += 64)),
    );
    // check transaction input index
    assert.strictEqual(
      index + 2,
      Number(
        '0x' +
          (await bitcoin.encode.reverseHex(
            txHex.slice(interpreterIndex, (interpreterIndex += 8)),
          )),
      ),
    );
    // p2wsh single sig htlc contains 4 witness items
    const singleSigHtlcWitnessItemCount: number =
      await bitcoin.data.varIntToNumber(
        txHex.slice(witnessStartIndex, (witnessStartIndex += 2)),
      );
    assert.strictEqual(4, singleSigHtlcWitnessItemCount);
    // first signature bytes to read is a single byte
    const htlcSigBytesToRead: number = await bitcoin.data.varIntToNumber(
      txHex.slice(witnessStartIndex, (witnessStartIndex += 2)),
    );
    assert.strictEqual(
      true,
      await bitcoin.crypto.verify(
        txHex.slice(
          witnessStartIndex,
          (witnessStartIndex += htlcSigBytesToRead * 2),
        ),
        await tx.getInputHashToSign(
          (await bitcoin.script.generateTimeLockScript(locktime)) +
            (await bitcoin.script.generateHashLockScript(secretHex)) +
            (await bitcoin.script.generateSingleSigScript(keypair.publicKey)),
          2,
          'segwit',
        ),
        // pubkey bytes to read is a single byte
        txHex.slice((witnessStartIndex += 2), (witnessStartIndex += 66)),
      ),
    );
    // secret hex bytes to read is a single byte
    const htlcSecretBytesToRead: number = await bitcoin.data.varIntToNumber(
      txHex.slice(witnessStartIndex, (witnessStartIndex += 2)),
    );
    assert.strictEqual(
      secretHex,
      txHex.slice(
        witnessStartIndex,
        (witnessStartIndex += htlcSecretBytesToRead * 2),
      ),
    );
    // redeem script check
    const htlcRedeemScriptBytesToRead: number =
      await bitcoin.data.varIntToNumber(
        txHex.slice(witnessStartIndex, (witnessStartIndex += 2)),
      );
    assert.strictEqual(
      (await bitcoin.script.generateTimeLockScript(locktime)) +
        (await bitcoin.script.generateHashLockScript(secretHex)) +
        (await bitcoin.script.generateSingleSigScript(keypair.publicKey)),
      txHex.slice(
        witnessStartIndex,
        (witnessStartIndex += htlcRedeemScriptBytesToRead * 2),
      ),
    );
    // check empty script sig as segwit
    assert.strictEqual(
      txHex.slice(interpreterIndex, (interpreterIndex += 2)),
      bitcoin.Opcode.OP_0,
    );
    // check input sequence and varint of script sig, default to fdffffff
    assert.strictEqual(
      txHex.slice(interpreterIndex, (interpreterIndex += 8)),
      'fdffffff',
    );

    // 4. validate p2wsh htlc multisig script sig
    // check transaction input tx hash
    assert.strictEqual(
      await bitcoin.encode.reverseHex(txHash),
      txHex.slice(interpreterIndex, (interpreterIndex += 64)),
    );
    // check transaction input index
    assert.strictEqual(
      index + 3,
      Number(
        '0x' +
          (await bitcoin.encode.reverseHex(
            txHex.slice(interpreterIndex, (interpreterIndex += 8)),
          )),
      ),
    );
    // p2wsh multi sig htlc contains 5 witness items
    const multiSigHtlcWitnessItemCount: number =
      await bitcoin.data.varIntToNumber(
        txHex.slice(witnessStartIndex, (witnessStartIndex += 2)),
      );
    assert.strictEqual(5, multiSigHtlcWitnessItemCount);
    // OP_0 for multisig
    assert.strictEqual(
      bitcoin.Opcode.OP_0,
      txHex.slice(witnessStartIndex, (witnessStartIndex += 2)),
    );
    // first signature bytes to read is a single byte
    const firstHtlcSigBytesToRead: number = await bitcoin.data.varIntToNumber(
      txHex.slice(witnessStartIndex, (witnessStartIndex += 2)),
    );
    assert.strictEqual(
      true,
      await bitcoin.crypto.verify(
        txHex.slice(
          witnessStartIndex,
          (witnessStartIndex += firstHtlcSigBytesToRead * 2),
        ),
        await tx.getInputHashToSign(
          (await bitcoin.script.generateTimeLockScript(locktime)) +
            (await bitcoin.script.generateHashLockScript(secretHex)) +
            (await bitcoin.script.generateMultiSigScript(2, [
              keypair.publicKey,
              keypair.publicKey,
              keypair.publicKey,
              keypair.publicKey,
            ])),
          3,
          'segwit',
        ),
        // pubkey bytes to read is a single byte
        keypair.publicKey,
      ),
    );
    // second signature bytes to read is a single byte
    const secondHtlcSigBytesToRead: number = await bitcoin.data.varIntToNumber(
      txHex.slice(witnessStartIndex, (witnessStartIndex += 2)),
    );
    assert.strictEqual(
      true,
      await bitcoin.crypto.verify(
        txHex.slice(
          witnessStartIndex,
          (witnessStartIndex += secondHtlcSigBytesToRead * 2),
        ),
        await tx.getInputHashToSign(
          (await bitcoin.script.generateTimeLockScript(locktime)) +
            (await bitcoin.script.generateHashLockScript(secretHex)) +
            (await bitcoin.script.generateMultiSigScript(2, [
              keypair.publicKey,
              keypair.publicKey,
              keypair.publicKey,
              keypair.publicKey,
            ])),
          3,
          'segwit',
        ),
        // pubkey bytes to read is a single byte
        keypair.publicKey,
      ),
    );
    // secret hex bytes to read is a single byte
    const htlcMultiSigSecretBytesToRead: number =
      await bitcoin.data.varIntToNumber(
        txHex.slice(witnessStartIndex, (witnessStartIndex += 2)),
      );
    assert.strictEqual(
      secretHex,
      txHex.slice(
        witnessStartIndex,
        (witnessStartIndex += htlcMultiSigSecretBytesToRead * 2),
      ),
    );
    // redeem script check(2-of-4 multisig htlc redeem script)
    const htlcMultiSigRedeemScriptBytesToRead: number =
      await bitcoin.data.varIntToNumber(
        txHex.slice(witnessStartIndex, (witnessStartIndex += 2)),
      );
    assert.strictEqual(
      (await bitcoin.script.generateTimeLockScript(locktime)) +
        (await bitcoin.script.generateHashLockScript(secretHex)) +
        (await bitcoin.script.generateMultiSigScript(2, [
          keypair.publicKey,
          keypair.publicKey,
          keypair.publicKey,
          keypair.publicKey,
        ])),
      txHex.slice(
        witnessStartIndex,
        (witnessStartIndex += htlcMultiSigRedeemScriptBytesToRead * 2),
      ),
    );
    // check empty script sig as segwit
    assert.strictEqual(
      txHex.slice(interpreterIndex, (interpreterIndex += 2)),
      bitcoin.Opcode.OP_0,
    );
    // check input sequence and varint of script sig, default to fdffffff
    assert.strictEqual(
      txHex.slice(interpreterIndex, (interpreterIndex += 8)),
      'fdffffff',
    );

    // 5. validate p2sh custom smart contract signing with
    // check transaction input tx hash
    assert.strictEqual(
      await bitcoin.encode.reverseHex(txHash),
      txHex.slice(interpreterIndex, (interpreterIndex += 64)),
    );
    // check transaction input index
    assert.strictEqual(
      index + 4,
      Number(
        '0x' +
          (await bitcoin.encode.reverseHex(
            txHex.slice(interpreterIndex, (interpreterIndex += 8)),
          )),
      ),
    );
    // p2wsh custom htlc contains 5 witness items
    const htlcWitnessItemCount: number = await bitcoin.data.varIntToNumber(
      txHex.slice(witnessStartIndex, (witnessStartIndex += 2)),
    );
    assert.strictEqual(4, htlcWitnessItemCount);
    // signature bytes to read is a single byte
    const customHtlcSigBytesToRead: number = await bitcoin.data.varIntToNumber(
      txHex.slice(witnessStartIndex, (witnessStartIndex += 2)),
    );
    assert.strictEqual(
      true,
      await bitcoin.crypto.verify(
        txHex.slice(
          witnessStartIndex,
          (witnessStartIndex += customHtlcSigBytesToRead * 2),
        ),
        await tx.getInputHashToSign(HTLC, 4, 'segwit'),
        // pubkey bytes to read is a single byte
        keypair.publicKey,
      ),
    );
    // second signature bytes to read is a single byte
    const customHtlcSecretBytesToRead: number =
      await bitcoin.data.varIntToNumber(
        txHex.slice(witnessStartIndex, (witnessStartIndex += 2)),
      );
    assert.strictEqual(
      secretHex,
      txHex.slice(
        witnessStartIndex,
        (witnessStartIndex += customHtlcSecretBytesToRead * 2),
      ),
    );
    // empty bytes to execute OP_ELSE
    assert.strictEqual(
      bitcoin.Opcode.OP_0,
      txHex.slice(witnessStartIndex, (witnessStartIndex += 2)),
    );
    // redeem script check(custom htlc redeem script)
    const customHtlcRedeemScriptBytesToRead: number =
      await bitcoin.data.varIntToNumber(
        txHex.slice(witnessStartIndex, (witnessStartIndex += 2)),
      );
    assert.strictEqual(
      HTLC,
      txHex.slice(
        witnessStartIndex,
        (witnessStartIndex += customHtlcRedeemScriptBytesToRead * 2),
      ),
    );
    // check empty script sig as segwit
    assert.strictEqual(
      txHex.slice(interpreterIndex, (interpreterIndex += 2)),
      bitcoin.Opcode.OP_0,
    );
    // check input sequence and varint of script sig, default to fdffffff
    assert.strictEqual(
      txHex.slice(interpreterIndex, (interpreterIndex += 8)),
      'fdffffff',
    );

    // check transaction locktime
    assert.strictEqual(
      Number('0x' + (await bitcoin.encode.reverseHex(txHex.slice(-8)))),
      locktime,
    );
  });
});
