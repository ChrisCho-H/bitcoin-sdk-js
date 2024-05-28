import { secp256k1 } from '@noble/curves/secp256k1';
import { bytesToHex } from '@noble/hashes/utils';

export interface KeyPair {
  publicKey: string;
  privateKey: string;
}

export const generateKeyPair = async (): Promise<KeyPair> => {
  const privateKey: Uint8Array = secp256k1.utils.randomPrivateKey();
  const publicKey: Uint8Array = secp256k1.getPublicKey(privateKey);
  return {
    publicKey: bytesToHex(publicKey),
    privateKey: bytesToHex(privateKey),
  };
};

export const getPublicKey = async (privateKey: string): Promise<string> => {
  return bytesToHex(secp256k1.getPublicKey(privateKey));
};
