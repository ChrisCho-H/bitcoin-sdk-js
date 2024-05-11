// ec
import * as assert from 'assert';
import { describe, it } from 'mocha';
import * as bitcoin from '../src/index.js';
describe('byte to hex test', () => {
    it('byte array converted to hex string', async () => {
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
describe('hex to byte test', () => {
    it('hex string converted to byte array', async () => {
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
describe('pad hex zero test', () => {
    it('hex string must be padded with zero from beginning', async () => {
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
describe('reverse hex test', () => {
    it('hex string reversed (mainly to make little endian)', async () => {
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
