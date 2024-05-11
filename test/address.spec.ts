//addr
import * as assert from 'assert';
import { describe, it } from 'mocha';
import * as bitcoin from '../src/index.js';

describe('address generate test', () => {
  it('p2pkh, p2wpkh, p2tr address must be generated', async () => {
    // Given
    const keypair: bitcoin.wallet.KeyPair =
      await bitcoin.wallet.generateKeyPair();
    // When
    const legacyAddress = await bitcoin.address.generateAddress(
      keypair.publicKey,
      'legacy',
    );
    const segwitAddress = await bitcoin.address.generateAddress(
      keypair.publicKey,
      'segwit',
    );
    const taprootAddress = await bitcoin.address.generateAddress(
      keypair.publicKey.slice(2),
      'taproot',
    );
    const legacyAddressTestnet = await bitcoin.address.generateAddress(
      keypair.publicKey,
      'legacy',
      'testnet',
    );
    const segwitAddressTestnet = await bitcoin.address.generateAddress(
      keypair.publicKey,
      'segwit',
      'testnet',
    );
    const taprootAddressTestnet = await bitcoin.address.generateAddress(
      keypair.publicKey.slice(2),
      'taproot',
      'testnet',
    );
    const hash160 = await bitcoin.encode.bytesToHex(
      await bitcoin.crypto.hash160(
        await bitcoin.encode.hexToBytes(keypair.publicKey),
      ),
    );
    // Then
    assert.strictEqual(
      await bitcoin.script.getScriptByAddress(legacyAddress),
      bitcoin.Opcode.OP_DUP +
        bitcoin.Opcode.OP_HASH160 +
        (await bitcoin.data.pushData(hash160)) + // anything smaller than 4c is byte length to read
        hash160 +
        bitcoin.Opcode.OP_EQUALVERIFY +
        bitcoin.Opcode.OP_CHECKSIG,
    );
    assert.strictEqual(
      await bitcoin.script.getScriptByAddress(segwitAddress),
      bitcoin.Opcode.OP_0 + (await bitcoin.data.pushData(hash160)) + hash160,
    );
    assert.strictEqual(
      await bitcoin.script.getScriptByAddress(taprootAddress),
      bitcoin.Opcode.OP_1 +
        (await bitcoin.data.pushData(keypair.publicKey.slice(2))) +
        keypair.publicKey.slice(2),
    );
    assert.strictEqual(
      await bitcoin.script.getScriptByAddress(legacyAddress),
      await bitcoin.script.getScriptByAddress(legacyAddressTestnet),
    );
    assert.strictEqual(
      await bitcoin.script.getScriptByAddress(segwitAddress),
      await bitcoin.script.getScriptByAddress(segwitAddressTestnet),
    );
    assert.strictEqual(
      await bitcoin.script.getScriptByAddress(taprootAddress),
      await bitcoin.script.getScriptByAddress(taprootAddressTestnet),
    );
  });
});

describe('script address generate test', () => {
  it('p2sh, p2wsh address must be generated', async () => {
    // Given
    const script: string = await bitcoin.script.generateTimeLockScript(
      500000000 - 1,
    );
    // When
    const legacyAddress = await bitcoin.address.generateScriptAddress(
      script,
      'legacy',
    );
    const segwitAddress = await bitcoin.address.generateScriptAddress(
      script,
      'segwit',
    );
    const legacyAddressTestnet = await bitcoin.address.generateScriptAddress(
      script,
      'legacy',
      'testnet',
    );
    const segwitAddressTestnet = await bitcoin.address.generateScriptAddress(
      script,
      'segwit',
      'testnet',
    );
    const hash160 = await bitcoin.encode.bytesToHex(
      await bitcoin.crypto.hash160(await bitcoin.encode.hexToBytes(script)),
    );
    const sha256 = await bitcoin.encode.bytesToHex(
      await bitcoin.crypto.sha256(await bitcoin.encode.hexToBytes(script)),
    );
    // Then
    assert.strictEqual(
      await bitcoin.script.getScriptByAddress(legacyAddress),
      bitcoin.Opcode.OP_HASH160 +
        (await bitcoin.data.pushData(hash160)) + // anything smaller than 4c is byte length to read
        hash160 +
        bitcoin.Opcode.OP_EQUAL,
    );
    assert.strictEqual(
      await bitcoin.script.getScriptByAddress(segwitAddress),
      bitcoin.Opcode.OP_0 + (await bitcoin.data.pushData(sha256)) + sha256,
    );
    assert.strictEqual(
      await bitcoin.script.getScriptByAddress(legacyAddress),
      await bitcoin.script.getScriptByAddress(legacyAddressTestnet),
    );
    assert.strictEqual(
      await bitcoin.script.getScriptByAddress(segwitAddress),
      await bitcoin.script.getScriptByAddress(segwitAddressTestnet),
    );
  });
});
