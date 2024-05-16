"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.base64ToBytes = exports.bytesToBase64 = exports.utf8ToBytes = exports.bytesToHex = exports.hexToBytes = exports.reverseHex = exports.padZeroHexN = void 0;
const utils_1 = require("@noble/hashes/utils");
const padZeroHexN = async (hex, n) => {
    return hex.padStart(n, '0');
};
exports.padZeroHexN = padZeroHexN;
const reverseHex = async (hex) => {
    return (0, exports.bytesToHex)((await (0, exports.hexToBytes)(hex)).reverse());
};
exports.reverseHex = reverseHex;
const hexToBytes = async (hex) => {
    return (0, utils_1.hexToBytes)(hex);
};
exports.hexToBytes = hexToBytes;
const bytesToHex = async (bytes) => {
    return (0, utils_1.bytesToHex)(bytes);
};
exports.bytesToHex = bytesToHex;
const utf8ToBytes = async (str) => {
    return (0, utils_1.utf8ToBytes)(str);
};
exports.utf8ToBytes = utf8ToBytes;
const bytesToBase64 = async (bytes) => {
    return btoa(String.fromCharCode(...bytes));
};
exports.bytesToBase64 = bytesToBase64;
const base64ToBytes = async (str) => {
    return Uint8Array.from(atob(str), (c) => c.charCodeAt(0));
};
exports.base64ToBytes = base64ToBytes;
