"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.sha256 = exports.ripemd160 = exports.hash256 = exports.hash160 = void 0;
const ripemd160_1 = require("@noble/hashes/ripemd160");
const sha256_1 = require("@noble/hashes/sha256");
const hash160 = async (hex) => {
    return await (0, exports.ripemd160)(await (0, exports.sha256)(hex));
};
exports.hash160 = hash160;
const hash256 = async (hex) => {
    return await (0, exports.sha256)(await (0, exports.sha256)(hex));
};
exports.hash256 = hash256;
const ripemd160 = async (hex) => {
    return (0, ripemd160_1.ripemd160)(hex);
};
exports.ripemd160 = ripemd160;
const sha256 = async (hex) => {
    return (0, sha256_1.sha256)(hex);
};
exports.sha256 = sha256;
