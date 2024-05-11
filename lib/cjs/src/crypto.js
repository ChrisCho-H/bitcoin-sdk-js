"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.verify = exports.sign = exports.sha256 = exports.ripemd160 = exports.hash256 = exports.hash160 = void 0;
const ripemd160_1 = require("@noble/hashes/ripemd160");
const sha256_1 = require("@noble/hashes/sha256");
const secp256k1_1 = require("@noble/curves/secp256k1");
const encode_js_1 = require("./encode.js");
const validator_js_1 = require("./validator.js");
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
const sign = async (msgHash, privkey, type = 'ecdsa', sigHashType = '01000000') => {
    // for validation
    await validator_js_1.Validator.validateKeyPair('', privkey, type);
    // convert to sighash default for schnorr taproot if input is sighash all
    if (sigHashType === '01000000' && type === 'schnorr')
        sigHashType = '';
    return ((type === 'ecdsa'
        ? secp256k1_1.secp256k1.sign(msgHash, privkey).toDERHex()
        : await (0, encode_js_1.bytesToHex)(secp256k1_1.schnorr.sign(msgHash, privkey))) +
        sigHashType.slice(0, 2));
};
exports.sign = sign;
const verify = async (signature, msgHash, pubkey, type = 'ecdsa', sigHashType = '01000000') => {
    // for validation
    await validator_js_1.Validator.validateKeyPair(pubkey, '', type);
    // convert to sighash default for schnorr taproot if input is sighash all
    if (!(sigHashType === '01000000' && type === 'schnorr'))
        signature = signature.slice(0, -2);
    return type === 'ecdsa'
        ? secp256k1_1.secp256k1.verify(signature, msgHash, pubkey)
        : secp256k1_1.schnorr.verify(signature, msgHash, pubkey);
};
exports.verify = verify;
