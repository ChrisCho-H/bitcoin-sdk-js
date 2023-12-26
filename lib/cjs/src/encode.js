"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.bytesToHex = exports.hexToBytes = exports.reverseHex = exports.padZeroHexN = void 0;
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
