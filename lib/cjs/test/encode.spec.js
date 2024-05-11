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
// ec
const assert = __importStar(require("assert"));
const mocha_1 = require("mocha");
const bitcoin = __importStar(require("../src/index.js"));
(0, mocha_1.describe)('byte to hex test', () => {
    (0, mocha_1.it)('byte array converted to hex string', async () => {
        // Given
        const bytes = crypto.getRandomValues(new Uint8Array(32));
        // When
        const hex = await bitcoin.encode.bytesToHex(bytes);
        // Then
        for (let i = 0; i < bytes.length; i++) {
            assert.strictEqual(bytes[i], parseInt(hex.substring(i * 2, i * 2 + 2), 16));
        }
    });
});
(0, mocha_1.describe)('hex to byte test', () => {
    (0, mocha_1.it)('hex string converted to byte array', async () => {
        // Given
        const hex = await bitcoin.encode.bytesToHex(crypto.getRandomValues(new Uint8Array(32)));
        // When
        const bytes = await bitcoin.encode.hexToBytes(hex);
        // Then
        for (let i = 0; i < bytes.length; i++) {
            assert.strictEqual(bytes[i], parseInt(hex.substring(i * 2, i * 2 + 2), 16));
        }
    });
});
(0, mocha_1.describe)('pad hex zero test', () => {
    (0, mocha_1.it)('hex string must be padded with zero from beginning', async () => {
        // Given
        const hex = await bitcoin.encode.bytesToHex(crypto.getRandomValues(new Uint8Array(32)));
        // When
        const hexPadded = await bitcoin.encode.padZeroHexN(hex, 128);
        // Then
        assert.strictEqual(hexPadded.length, 128);
        for (let i = 0; i < 64; i++) {
            assert.strictEqual(hexPadded[i], '0');
        }
    });
});
(0, mocha_1.describe)('reverse hex test', () => {
    (0, mocha_1.it)('hex string reversed (mainly to make little endian)', async () => {
        // Given
        const hex = await bitcoin.encode.bytesToHex(crypto.getRandomValues(new Uint8Array(32)));
        // When
        const reversedHex = await bitcoin.encode.reverseHex(hex);
        // Then
        for (let i = 0; i < hex.length; i++) {
            assert.strictEqual(parseInt(hex.substring(i * 2, i * 2 + 2), 16), parseInt(reversedHex.substring(hex.length - (i * 2 + 2), hex.length - i * 2), 16));
        }
    });
});
