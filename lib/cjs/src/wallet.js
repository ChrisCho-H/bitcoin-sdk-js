"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.generateKeyPair = void 0;
const secp256k1_1 = require("@noble/curves/secp256k1");
const utils_1 = require("@noble/hashes/utils");
const generateKeyPair = async () => {
    const privateKey = secp256k1_1.secp256k1.utils.randomPrivateKey();
    const publicKey = secp256k1_1.secp256k1.getPublicKey(privateKey);
    return {
        publicKey: (0, utils_1.bytesToHex)(publicKey),
        privateKey: (0, utils_1.bytesToHex)(privateKey),
    };
};
exports.generateKeyPair = generateKeyPair;
