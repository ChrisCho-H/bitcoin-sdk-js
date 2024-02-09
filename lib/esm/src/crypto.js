import { ripemd160 as _ripemd160 } from '@noble/hashes/ripemd160';
import { sha256 as _sha256 } from '@noble/hashes/sha256';
import { secp256k1 } from '@noble/curves/secp256k1';
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
export const sign = async (msgHash, privkey) => {
    const sigHashType = '01000000';
    return secp256k1.sign(msgHash, privkey).toDERHex() + sigHashType.slice(0, 2);
};
