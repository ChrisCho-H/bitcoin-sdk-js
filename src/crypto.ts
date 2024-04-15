import { ripemd160 as _ripemd160 } from '@noble/hashes/ripemd160';
import { sha256 as _sha256 } from '@noble/hashes/sha256';
import { schnorr, secp256k1 } from '@noble/curves/secp256k1';
import { bytesToHex } from './encode.js';

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
  // convert to sighash default for schnorr taproot if input is sighash all
  if (sigHashType === '01000000' && type === 'schnorr') sigHashType = '';
  return (
    (type === 'ecdsa'
      ? secp256k1.sign(msgHash, privkey).toDERHex()
      : await bytesToHex(schnorr.sign(msgHash, privkey))) +
    sigHashType.slice(0, 2)
  );
};
