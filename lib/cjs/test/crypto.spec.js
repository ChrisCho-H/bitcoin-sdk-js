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
const assert = __importStar(require("assert"));
const mocha_1 = require("mocha");
const bitcoin = __importStar(require("../src/index.js"));
(0, mocha_1.describe)('sha256 test', () => {
    (0, mocha_1.it)('sha256 digest must be same', async () => {
        // Given
        const bytes = crypto.getRandomValues(new Uint8Array(32));
        // When
        const sha256Node = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
        const sha256Bit = await bitcoin.crypto.sha256(bytes);
        // Then
        for (let i = 0; i < sha256Node.byteLength; i++)
            assert.strictEqual(sha256Node[i], sha256Bit[i]);
    });
});
(0, mocha_1.describe)('hash256 test', () => {
    (0, mocha_1.it)('hash256 digest must be double sha256', async () => {
        // Given
        const bytes = crypto.getRandomValues(new Uint8Array(32));
        // When
        const hash256Node = new Uint8Array(await crypto.subtle.digest('SHA-256', await crypto.subtle.digest('SHA-256', bytes)));
        const hash256Bit = await bitcoin.crypto.hash256(bytes);
        // Then
        for (let i = 0; i < hash256Node.byteLength; i++)
            assert.strictEqual(hash256Node[i], hash256Bit[i]);
    });
});
(0, mocha_1.describe)('hash160 and ripemd test', () => {
    (0, mocha_1.it)('hash160 digest must be same with ripemd160(sha256(m))', async () => {
        // Given
        const bytes = crypto.getRandomValues(new Uint8Array(32));
        // When
        const hash160Node = await bitcoin.crypto.hash160(bytes);
        const hash160Bit = await bitcoin.crypto.ripemd160(await bitcoin.crypto.sha256(bytes));
        // Then
        for (let i = 0; i < hash160Node.byteLength; i++)
            assert.strictEqual(hash160Node[i], hash160Bit[i]);
    });
});
(0, mocha_1.describe)('sign and verify test', () => {
    (0, mocha_1.it)('signature must be verified as true', async () => {
        // Given
        const bytes = crypto.getRandomValues(new Uint8Array(32));
        const keypair = await bitcoin.wallet.generateKeyPair();
        // When
        const ecdsaSig = await bitcoin.crypto.sign(bytes, keypair.privateKey, 'ecdsa');
        const schnorrSig = await bitcoin.crypto.sign(bytes, keypair.privateKey, 'schnorr');
        // Then
        assert.strictEqual(await bitcoin.crypto.verify(ecdsaSig, bytes, keypair.publicKey, 'ecdsa'), true);
        assert.strictEqual(await bitcoin.crypto.verify(schnorrSig, bytes, keypair.publicKey.slice(2), 'schnorr'), true);
    });
});
