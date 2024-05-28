import { secp256k1 } from '@noble/curves/secp256k1';
import { bytesToHex } from '@noble/hashes/utils';
export const generateKeyPair = async () => {
    const privateKey = secp256k1.utils.randomPrivateKey();
    const publicKey = secp256k1.getPublicKey(privateKey);
    return {
        publicKey: bytesToHex(publicKey),
        privateKey: bytesToHex(privateKey),
    };
};
export const getPublicKey = async (privateKey) => {
    return bytesToHex(secp256k1.getPublicKey(privateKey));
};
