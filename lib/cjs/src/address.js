"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.generateScriptAddress = exports.generateAddress = void 0;
const utils_1 = require("@noble/hashes/utils");
const bs58_1 = __importDefault(require("bs58"));
const crypto_js_1 = require("./crypto.js");
const generateAddress = async (pubkey, network = 'mainnet') => {
    if (pubkey.length !== 66)
        throw new Error('pubkey must be compressed 33 bytes');
    const pubkeyHash = await (0, crypto_js_1.hash160)((0, utils_1.hexToBytes)(pubkey));
    const version = new Uint8Array([
        network === 'mainnet' ? 0x1e : 0x71,
    ]);
    const checksum = (await (0, crypto_js_1.hash256)(new Uint8Array([...version, ...pubkeyHash]))).slice(0, 4);
    const bs58encoded = bs58_1.default.encode(new Uint8Array([...version, ...pubkeyHash, ...checksum]));
    return bs58encoded;
};
exports.generateAddress = generateAddress;
const generateScriptAddress = async (script, network = 'mainnet') => {
    if (script.length > 1040)
        throw new Error('Redeem script must be less than 520 bytes');
    const scriptHash = await (0, crypto_js_1.hash160)((0, utils_1.hexToBytes)(script));
    const version = new Uint8Array([
        network === 'mainnet' ? 0x16 : 0xc4,
    ]);
    const checksum = (await (0, crypto_js_1.hash256)(new Uint8Array([...version, ...scriptHash]))).slice(0, 4);
    const bs58encoded = bs58_1.default.encode(new Uint8Array([...version, ...scriptHash, ...checksum]));
    return bs58encoded;
};
exports.generateScriptAddress = generateScriptAddress;
