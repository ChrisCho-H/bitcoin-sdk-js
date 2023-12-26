import { bytesToHex as _bytesToHex, hexToBytes as _hexToBytes, } from '@noble/hashes/utils';
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
