"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.scriptNum = exports.base64ToBytes = exports.bytesToBase64 = exports.utf8ToBytes = exports.bytesToHex = exports.hexToBytes = exports.reverseHex = exports.padZeroHexN = void 0;
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
const scriptNum = async (num) => {
    const abs = Math.abs(num);
    if (abs <= 0x7f) {
        num = num > 0 ? num : abs + 0x80;
        return await (0, exports.reverseHex)(await (0, exports.padZeroHexN)(num.toString(16), 2));
    }
    else if (abs <= 0x7fff) {
        num = num > 0 ? num : abs + 0x8000;
        return await (0, exports.reverseHex)(await (0, exports.padZeroHexN)(num.toString(16), 4));
    }
    else if (abs <= 0x7fffff) {
        num = num > 0 ? num : abs + 0x800000;
        return await (0, exports.reverseHex)(await (0, exports.padZeroHexN)(num.toString(16), 6));
    }
    else if (abs <= 0x7fffffff) {
        num = num > 0 ? num : abs + 0x80000000;
        return await (0, exports.reverseHex)(await (0, exports.padZeroHexN)(num.toString(16), 8));
    }
    else if (abs <= 0x7fffffffff) {
        num = num > 0 ? num : abs + 0x8000000000;
        return await (0, exports.reverseHex)(await (0, exports.padZeroHexN)(num.toString(16), 10));
    }
    else {
        throw new Error('Number can be maximum 5 byte int');
    }
};
exports.scriptNum = scriptNum;
