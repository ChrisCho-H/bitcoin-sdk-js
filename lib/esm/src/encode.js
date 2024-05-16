import { bytesToHex as _bytesToHex, hexToBytes as _hexToBytes, utf8ToBytes as _utf8ToBytes, } from '@noble/hashes/utils';
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
