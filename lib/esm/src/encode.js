import { bytesToHex as _bytesToHex, hexToBytes as _hexToBytes, utf8ToBytes as _utf8ToBytes, } from '@noble/hashes/utils';
import { Opcode } from './opcode.js';
export const padZeroHexN = async (hex, n) => {
    return hex.padStart(n, '0');
};
export const reverseHex = async (hex) => {
    return bytesToHex((await hexToBytes(hex)).reverse());
};
export const hexToBytes = async (hex) => {
    return _hexToBytes(hex);
};
export const bytesToHex = async (bytes) => {
    return _bytesToHex(bytes);
};
export const utf8ToBytes = async (str) => {
    return _utf8ToBytes(str);
};
export const bytesToBase64 = async (bytes) => {
    return btoa(String.fromCharCode(...bytes));
};
export const base64ToBytes = async (str) => {
    return Uint8Array.from(atob(str), (c) => c.charCodeAt(0));
};
export const scriptNum = async (num) => {
    // bip62 number push
    if (num === 0)
        return Opcode.OP_0;
    if (num >= 1 && num <= 16)
        return (0x50 + num).toString(16);
    if (num === -1)
        return Opcode.OP_1NEGATE;
    const abs = Math.abs(num);
    if (abs <= 0x7f) {
        num = num > 0 ? num : abs + 0x80;
        return await reverseHex(await padZeroHexN(num.toString(16), 2));
    }
    else if (abs <= 0x7fff) {
        num = num > 0 ? num : abs + 0x8000;
        return await reverseHex(await padZeroHexN(num.toString(16), 4));
    }
    else if (abs <= 0x7fffff) {
        num = num > 0 ? num : abs + 0x800000;
        return await reverseHex(await padZeroHexN(num.toString(16), 6));
    }
    else if (abs <= 0x7fffffff) {
        num = num > 0 ? num : abs + 0x80000000;
        return await reverseHex(await padZeroHexN(num.toString(16), 8));
    }
    else if (abs <= 0x7fffffffff) {
        num = num > 0 ? num : abs + 0x8000000000;
        return await reverseHex(await padZeroHexN(num.toString(16), 10));
    }
    else {
        throw new Error('Number can be maximum 5 byte int');
    }
};
