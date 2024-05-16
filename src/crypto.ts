import { ripemd160 as _ripemd160 } from '@noble/hashes/ripemd160';
import { sha256 as _sha256 } from '@noble/hashes/sha256';
import { schnorr, secp256k1 } from '@noble/curves/secp256k1';
import {
  bytesToHex,
  padZeroHexN,
  hexToBytes,
  utf8ToBytes,
  bytesToBase64,
  base64ToBytes,
} from './encode.js';
import { Validator } from './validator.js';
import { getVarInt } from './data.js';
import { generateSingleSigScript, getScriptByAddress } from './script.js';
import { Opcode } from './opcode.js';
import { Transaction } from './transaction.js';
import { getTapTag, getTapTweak, getTapTweakedPrivkey } from './tapscript.js';

export const hash160 = async (hex: Uint8Array): Promise<Uint8Array> => {
  return await ripemd160(await sha256(hex));
};

export const hash256 = async (hex: Uint8Array): Promise<Uint8Array> => {
  return await sha256(await sha256(hex));
};

export const ripemd160 = async (hex: Uint8Array): Promise<Uint8Array> => {
  return _ripemd160(hex);
};

export const sha256 = async (hex: Uint8Array): Promise<Uint8Array> => {
  return _sha256(hex);
};

export const sign = async (
  msgHash: Uint8Array,
  privkey: string,
  type: 'ecdsa' | 'schnorr' = 'ecdsa',
  sigHashType = '01000000',
): Promise<string> => {
  // for validation
  await Validator.validateKeyPair('', privkey, type);

  // convert to sighash default for schnorr taproot if input is sighash all
  if (sigHashType === '01000000' && type === 'schnorr') sigHashType = '';
  return (
    (type === 'ecdsa'
      ? secp256k1.sign(msgHash, privkey).toDERHex()
      : await bytesToHex(schnorr.sign(msgHash, privkey))) +
    sigHashType.slice(0, 2)
  );
};

export const verify = async (
  signature: string,
  msgHash: Uint8Array,
  pubkey: string,
  type: 'ecdsa' | 'schnorr' = 'ecdsa',
  sigHashType = '01000000',
): Promise<boolean> => {
  // for validation
  await Validator.validateKeyPair(pubkey, '', type);

  // convert to sighash default for schnorr taproot if input is sighash all
  if (!(sigHashType === '01000000' && type === 'schnorr'))
    signature = signature.slice(0, -2);
  return type === 'ecdsa'
    ? secp256k1.verify(signature, msgHash, pubkey)
    : schnorr.verify(signature, msgHash, pubkey);
};

export const signMessage = async (
  msg: string,
  privkey: string,
  address: string,
): Promise<string> => {
  const script = await getScriptByAddress(address);
  // legacy p2pkh adress use legacy signing process
  if (script.slice(0, 2) === Opcode.OP_DUP) {
    const prefix = await utf8ToBytes('\x18Bitcoin Signed Message:\n');
    const msgHex = await utf8ToBytes(msg);

    const len = await getVarInt(msgHex.length);
    const msgHash = await hash256(
      new Uint8Array([...prefix, ...(await hexToBytes(len)), ...msgHex]),
    );
    const sig = secp256k1.sign(msgHash, privkey);
    return bytesToBase64(
      new Uint8Array([sig.recovery + 31, ...sig.toCompactRawBytes()]),
    );
  } else {
    const pubkey: string = await bytesToHex(secp256k1.getPublicKey(privkey));
    const txToSign: Transaction = await _getVirtualTx(msg, script);
    // segwit p2wpkh and taproot p2tr use bip322 signing processs
    if (script.slice(0, 2) === Opcode.OP_0) {
      await txToSign.signInput(pubkey, privkey, 0);
    } else if (script.slice(0, 2) === Opcode.OP_1) {
      const tapTweak: Uint8Array = await getTapTweak(pubkey.slice(2));
      const tweakedPrivKey: string = await getTapTweakedPrivkey(
        privkey,
        tapTweak,
      );
      await txToSign.signInput(
        '',
        tweakedPrivKey,
        0,
        'taproot',
        '',
        '',
        '01_TRICK_SIGHASH_ALL', // trick to insert SIGHASH_ALL in taproot(not to convert to SIGHASH_DEFAULT)
      );
    } else {
      throw new Error('Only p2pkh, p2wpkh, p2tr address are supported now');
    }
    // return private witness field
    return bytesToBase64(await hexToBytes((txToSign as any)._witness.get(0)));
  }
};

export const verifyMessage = async (
  msg: string,
  signature: string,
  address: string,
): Promise<boolean> => {
  const signatureHex = await bytesToHex(await base64ToBytes(signature));
  const script = await getScriptByAddress(address);
  // legacy p2pkh adress use legacy verifying process
  if (script.slice(0, 2) === Opcode.OP_DUP) {
    const prefix = await utf8ToBytes('\x18Bitcoin Signed Message:\n');
    const msgHex = await utf8ToBytes(msg);
    const len = await getVarInt(msgHex.length);
    const msgHash = await hash256(
      new Uint8Array([...prefix, ...(await hexToBytes(len)), ...msgHex]),
    );

    const pubkeyHash = script.slice(6, 6 + 40);

    const pubkey = secp256k1.Signature.fromCompact(signatureHex.slice(2))
      .addRecoveryBit(parseInt(signatureHex.slice(0, 2), 16) - 0x1f)
      .recoverPublicKey(msgHash)
      .toRawBytes();

    return (await bytesToHex(await hash160(pubkey))) === pubkeyHash;
  } else {
    const txToSign: Transaction = await _getVirtualTx(msg, script);
    // segwit p2wpkh and taproot p2tr use bip322 signing processs
    if (script.slice(0, 2) === Opcode.OP_0) {
      const sigLen = parseInt(signatureHex.slice(2, 4), 16) * 2;
      const sig = signatureHex.slice(4, 4 + sigLen - 2); // remove sighash_type, varint
      const pubkey = signatureHex.slice(6 + sigLen); // remove varint
      const scriptCode = await generateSingleSigScript(pubkey);
      const msgHash: Uint8Array = await txToSign.getInputHashToSign(
        scriptCode,
        0,
        'segwit',
      );
      return secp256k1.verify(sig, msgHash, pubkey);
    } else if (script.slice(0, 2) === Opcode.OP_1) {
      const sig = signatureHex.slice(4, 132);
      const pubkey = script.slice(4);
      const msgHash: Uint8Array = await txToSign.getInputHashToSign(
        '',
        0,
        'taproot',
        '01_TRICK_SIGHASH_ALL', // trick to insert SIGHASH_ALL in taproot(not to convert to SIGHASH_DEFAULT)
      );
      return schnorr.verify(sig, msgHash, pubkey);
    }
    throw new Error('Only p2pkh, p2wpkh, p2tr address are supported now');
  }
};

const _getVirtualTx = async (
  msg: string,
  script: string,
): Promise<Transaction> => {
  // build tx to spend
  const txToSpend: Transaction = new Transaction();
  await txToSpend.setVersion(0);
  await txToSpend.addInput({
    txHash: await padZeroHexN('', 64),
    index: 0xffffffff,
    value: 0, // not required actually
    sequence: '00000000',
  });
  await txToSpend.addOutput({
    script: script,
    value: 0,
  });
  const msgHash = await bytesToHex(
    await sha256(
      new Uint8Array([
        ...(await getTapTag(await utf8ToBytes('BIP0322-signed-message'))),
        ...(await utf8ToBytes(msg)),
      ]),
    ),
  );
  await txToSpend.signInputByScriptSig(
    ['', msgHash], // OP_0 PUSH32[ message_hash ]
    0,
    'legacy', // inside script sig, not witness
  );

  // build tx to sign
  const txToSign: Transaction = new Transaction();
  await txToSign.setVersion(0);
  await txToSign.addInput({
    txHash: await txToSpend.getId(),
    index: 0,
    value: 0, // not required actually
    sequence: '00000000',
    script: script,
  });
  await txToSign.addOutput({
    script: Opcode.OP_RETURN,
    value: 0,
  });

  return txToSign;
};
