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

export const scriptNum = async (num: number): Promise<string> => {
  const abs = Math.abs(num);
  if (abs <= 0x7f) {
    num = num > 0 ? num : abs + 0x80;
    return await reverseHex(await padZeroHexN(num.toString(16), 2));
  } else if (abs <= 0x7fff) {
    num = num > 0 ? num : abs + 0x8000;
    return await reverseHex(await padZeroHexN(num.toString(16), 4));
  } else if (abs <= 0x7fffff) {
    num = num > 0 ? num : abs + 0x800000;
    return await reverseHex(await padZeroHexN(num.toString(16), 6));
  } else if (abs <= 0x7fffffff) {
    num = num > 0 ? num : abs + 0x80000000;
    return await reverseHex(await padZeroHexN(num.toString(16), 8));
  } else if (abs <= 0x7fffffffff) {
    num = num > 0 ? num : abs + 0x8000000000;
    return await reverseHex(await padZeroHexN(num.toString(16), 10));
  } else {
    throw new Error('Number can be maximum 5 byte int');
  }
};
