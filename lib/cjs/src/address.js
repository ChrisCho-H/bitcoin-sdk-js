"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.generateScriptAddress = exports.generateAddress = void 0;
const utils_1 = require("@noble/hashes/utils");
const bs58_1 = __importDefault(require("bs58"));
const crypto_js_1 = require("./crypto.js");
const bech32_1 = require("bech32");
const validator_js_1 = require("./validator.js");
const generateAddress = async (pubkey, type = 'segwit', network = 'mainnet') => {
    await validator_js_1.Validator.validateKeyPair(pubkey, '', type === 'taproot' ? 'schnorr' : 'ecdsa');
    if (type === 'taproot') {
        const words = bech32_1.bech32m.toWords((0, utils_1.hexToBytes)(pubkey));
        words.unshift(1); // taproot is segwit version 1
        return bech32_1.bech32m.encode(network === 'mainnet' ? 'bc' : 'tb', words);
    }
    const pubkeyHash = await (0, crypto_js_1.hash160)((0, utils_1.hexToBytes)(pubkey));
    if (type === 'segwit') {
        const words = bech32_1.bech32.toWords(pubkeyHash);
        words.unshift(0); // segwit version
        return bech32_1.bech32.encode(network === 'mainnet' ? 'bc' : 'tb', words);
    }
    else {
        const version = new Uint8Array([
            network === 'mainnet' ? 0x00 : 0x6f,
        ]);
        const checksum = (await (0, crypto_js_1.hash256)(new Uint8Array([...version, ...pubkeyHash]))).slice(0, 4);
        return bs58_1.default.encode(new Uint8Array([...version, ...pubkeyHash, ...checksum]));
    }
};
exports.generateAddress = generateAddress;
const generateScriptAddress = async (script, type = 'segwit', network = 'mainnet') => {
    await validator_js_1.Validator.validateRedeemScript(script);
    const scriptHash = type === 'segwit'
        ? await (0, crypto_js_1.sha256)((0, utils_1.hexToBytes)(script))
        : await (0, crypto_js_1.hash160)((0, utils_1.hexToBytes)(script));
    if (type === 'segwit') {
        const words = bech32_1.bech32.toWords(scriptHash);
        words.unshift(0); // segwit version
        return bech32_1.bech32.encode(network === 'mainnet' ? 'bc' : 'tb', words);
    }
    else {
        const version = new Uint8Array([
            network === 'mainnet' ? 0x05 : 0xc4,
        ]);
        const checksum = (await (0, crypto_js_1.hash256)(new Uint8Array([...version, ...scriptHash]))).slice(0, 4);
        return bs58_1.default.encode(new Uint8Array([...version, ...scriptHash, ...checksum]));
    }
};
exports.generateScriptAddress = generateScriptAddress;
