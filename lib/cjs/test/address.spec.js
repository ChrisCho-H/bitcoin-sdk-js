"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
Object.defineProperty(exports, "__esModule", { value: true });
//addr
const assert = __importStar(require("assert"));
const mocha_1 = require("mocha");
const bitcoin = __importStar(require("../src/index.js"));
(0, mocha_1.describe)('address generate test', () => {
    (0, mocha_1.it)('p2pkh, p2wpkh, p2tr address must be generated', async () => {
        // Given
        const keypair = await bitcoin.wallet.generateKeyPair();
        // When
        const legacyAddress = await bitcoin.address.generateAddress(keypair.publicKey, 'legacy');
        const segwitAddress = await bitcoin.address.generateAddress(keypair.publicKey, 'segwit');
        const taprootAddress = await bitcoin.address.generateAddress(keypair.publicKey.slice(2), 'taproot');
        const legacyAddressTestnet = await bitcoin.address.generateAddress(keypair.publicKey, 'legacy', 'testnet');
        const segwitAddressTestnet = await bitcoin.address.generateAddress(keypair.publicKey, 'segwit', 'testnet');
        const taprootAddressTestnet = await bitcoin.address.generateAddress(keypair.publicKey.slice(2), 'taproot', 'testnet');
        const hash160 = await bitcoin.encode.bytesToHex(await bitcoin.crypto.hash160(await bitcoin.encode.hexToBytes(keypair.publicKey)));
        // Then
        assert.strictEqual(await bitcoin.script.getScriptByAddress(legacyAddress), bitcoin.Opcode.OP_DUP +
            bitcoin.Opcode.OP_HASH160 +
            (await bitcoin.data.pushData(hash160)) + // anything smaller than 4c is byte length to read
            hash160 +
            bitcoin.Opcode.OP_EQUALVERIFY +
            bitcoin.Opcode.OP_CHECKSIG);
        assert.strictEqual(await bitcoin.script.getScriptByAddress(segwitAddress), bitcoin.Opcode.OP_0 + (await bitcoin.data.pushData(hash160)) + hash160);
        assert.strictEqual(await bitcoin.script.getScriptByAddress(taprootAddress), bitcoin.Opcode.OP_1 +
            (await bitcoin.data.pushData(keypair.publicKey.slice(2))) +
            keypair.publicKey.slice(2));
        assert.strictEqual(await bitcoin.script.getScriptByAddress(legacyAddress), await bitcoin.script.getScriptByAddress(legacyAddressTestnet));
        assert.strictEqual(await bitcoin.script.getScriptByAddress(segwitAddress), await bitcoin.script.getScriptByAddress(segwitAddressTestnet));
        assert.strictEqual(await bitcoin.script.getScriptByAddress(taprootAddress), await bitcoin.script.getScriptByAddress(taprootAddressTestnet));
    });
});
(0, mocha_1.describe)('script address generate test', () => {
    (0, mocha_1.it)('p2sh, p2wsh address must be generated', async () => {
        // Given
        const script = await bitcoin.script.generateTimeLockScript(500000000 - 1);
        // When
        const legacyAddress = await bitcoin.address.generateScriptAddress(script, 'legacy');
        const segwitAddress = await bitcoin.address.generateScriptAddress(script, 'segwit');
        const legacyAddressTestnet = await bitcoin.address.generateScriptAddress(script, 'legacy', 'testnet');
        const segwitAddressTestnet = await bitcoin.address.generateScriptAddress(script, 'segwit', 'testnet');
        const hash160 = await bitcoin.encode.bytesToHex(await bitcoin.crypto.hash160(await bitcoin.encode.hexToBytes(script)));
        const sha256 = await bitcoin.encode.bytesToHex(await bitcoin.crypto.sha256(await bitcoin.encode.hexToBytes(script)));
        // Then
        assert.strictEqual(await bitcoin.script.getScriptByAddress(legacyAddress), bitcoin.Opcode.OP_HASH160 +
            (await bitcoin.data.pushData(hash160)) + // anything smaller than 4c is byte length to read
            hash160 +
            bitcoin.Opcode.OP_EQUAL);
        assert.strictEqual(await bitcoin.script.getScriptByAddress(segwitAddress), bitcoin.Opcode.OP_0 + (await bitcoin.data.pushData(sha256)) + sha256);
        assert.strictEqual(await bitcoin.script.getScriptByAddress(legacyAddress), await bitcoin.script.getScriptByAddress(legacyAddressTestnet));
        assert.strictEqual(await bitcoin.script.getScriptByAddress(segwitAddress), await bitcoin.script.getScriptByAddress(segwitAddressTestnet));
    });
});
