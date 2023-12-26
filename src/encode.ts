import {
  bytesToHex as _bytesToHex,
  hexToBytes as _hexToBytes,
} from '@noble/hashes/utils';

export const padZeroHexN = async (hex: string, n: number): Promise<string> => {
  return hex.padStart(n, '0');
};

export const reverseHex = async (hex: string): Promise<string> => {
  return bytesToHex((await hexToBytes(hex)).reverse());
};

export const hexToBytes = async (hex: string): Promise<Uint8Array> => {
  return _hexToBytes(hex);
};

export const bytesToHex = async (bytes: Uint8Array): Promise<string> => {
  return _bytesToHex(bytes);
};
