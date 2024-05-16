import {
  bytesToHex as _bytesToHex,
  hexToBytes as _hexToBytes,
  utf8ToBytes as _utf8ToBytes,
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

export const utf8ToBytes = async (str: string): Promise<Uint8Array> => {
  return _utf8ToBytes(str);
};

export const bytesToBase64 = async (bytes: Uint8Array): Promise<string> => {
  return btoa(String.fromCharCode(...bytes));
};

export const base64ToBytes = async (str: string): Promise<Uint8Array> => {
  return Uint8Array.from(atob(str), (c) => c.charCodeAt(0));
};
