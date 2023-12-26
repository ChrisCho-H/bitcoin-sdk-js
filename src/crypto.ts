import { ripemd160 as _ripemd160 } from '@noble/hashes/ripemd160';
import { sha256 as _sha256 } from '@noble/hashes/sha256';

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
