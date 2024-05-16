import * as assert from 'assert';
import { describe, it } from 'mocha';
import * as bitcoin from '../src/index.js';

describe('sha256 test', () => {
  it('sha256 digest must be same', async () => {
    // Given
    const bytes: Uint8Array = crypto.getRandomValues(new Uint8Array(32));
    // When
    const sha256Node = new Uint8Array(
      await crypto.subtle.digest('SHA-256', bytes),
    );
    const sha256Bit = await bitcoin.crypto.sha256(bytes);
    // Then
    for (let i = 0; i < sha256Node.byteLength; i++)
      assert.strictEqual(sha256Node[i], sha256Bit[i]);
  });
});

describe('hash256 test', () => {
  it('hash256 digest must be double sha256', async () => {
    // Given
    const bytes: Uint8Array = crypto.getRandomValues(new Uint8Array(32));
    // When
    const hash256Node = new Uint8Array(
      await crypto.subtle.digest(
        'SHA-256',
        await crypto.subtle.digest('SHA-256', bytes),
      ),
    );
    const hash256Bit = await bitcoin.crypto.hash256(bytes);
    // Then
    for (let i = 0; i < hash256Node.byteLength; i++)
      assert.strictEqual(hash256Node[i], hash256Bit[i]);
  });
});

describe('hash160 and ripemd test', () => {
  it('hash160 digest must be same with ripemd160(sha256(m))', async () => {
    // Given
    const bytes: Uint8Array = crypto.getRandomValues(new Uint8Array(32));
    // When
    const hash160Node = await bitcoin.crypto.hash160(bytes);
    const hash160Bit = await bitcoin.crypto.ripemd160(
      await bitcoin.crypto.sha256(bytes),
    );
    // Then
    for (let i = 0; i < hash160Node.byteLength; i++)
      assert.strictEqual(hash160Node[i], hash160Bit[i]);
  });
});

describe('sign and verify test', () => {
  it('signature must be verified as true', async () => {
    // Given
    const bytes: Uint8Array = crypto.getRandomValues(new Uint8Array(32));
    const keypair: bitcoin.wallet.KeyPair =
      await bitcoin.wallet.generateKeyPair();
    // When
    const ecdsaSig = await bitcoin.crypto.sign(
      bytes,
      keypair.privateKey,
      'ecdsa',
    );
    const schnorrSig = await bitcoin.crypto.sign(
      bytes,
      keypair.privateKey,
      'schnorr',
    );
    // Then
    assert.strictEqual(
      await bitcoin.crypto.verify(ecdsaSig, bytes, keypair.publicKey, 'ecdsa'),
      true,
    );
    assert.strictEqual(
      await bitcoin.crypto.verify(
        schnorrSig,
        bytes,
        keypair.publicKey.slice(2),
        'schnorr',
      ),
      true,
    );
  });
});

describe('sign and verify message test', () => {
  it('signature must be verified as true', async () => {
    // Given
    const keyPair = await bitcoin.wallet.generateKeyPair();
    const privkey = keyPair.privateKey;
    const pubkey = keyPair.publicKey;
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
    const msg: string = await bitcoin.encode.bytesToHex(
      crypto.getRandomValues(new Uint8Array(32)),
    );
    // When
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
    // Then
    assert.strictEqual(
      await bitcoin.crypto.verifyMessage(msg, sigLegacy, legacyAddress),
      true,
    );
    assert.strictEqual(
      await bitcoin.crypto.verifyMessage(msg, sigSegwit, segwitAddress),
      true,
    );

    assert.strictEqual(
      await bitcoin.crypto.verifyMessage(msg, sigTap, tapAddress),
      true,
    );
  });
});
