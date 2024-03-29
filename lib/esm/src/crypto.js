import { ripemd160 as _ripemd160 } from '@noble/hashes/ripemd160';
import { sha256 as _sha256 } from '@noble/hashes/sha256';
import { schnorr, secp256k1 } from '@noble/curves/secp256k1';
import { bytesToHex } from './encode.js';
export const hash160 = async (hex) => {
    return await ripemd160(await sha256(hex));
};
export const hash256 = async (hex) => {
    return await sha256(await sha256(hex));
};
export const ripemd160 = async (hex) => {
    return _ripemd160(hex);
};
export const sha256 = async (hex) => {
    return _sha256(hex);
};
export const sign = async (msgHash, privkey, sigHashType = '01000000', type = 'secp256k1') => {
    return ((type === 'secp256k1'
        ? secp256k1.sign(msgHash, privkey).toDERHex()
        : await bytesToHex(schnorr.sign(msgHash, privkey))) +
        sigHashType.slice(0, 2));
};
