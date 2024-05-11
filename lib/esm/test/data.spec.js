// data
import * as assert from 'assert';
import { describe, it } from 'mocha';
import * as bitcoin from '../src/index.js';
describe('get varirable int test', () => {
    it('number converted to bitcoin varInt', async () => {
        // Given
        const num1 = Math.floor(Math.random() * (252 - 0 + 1) + 0);
        const num2 = Math.floor(Math.random() * (65535 - 253 + 1) + 253);
        const num3 = Math.floor(Math.random() * (4294967295 - 65536 + 1) + 65536);
        const num4 = Math.floor(Math.random() * (Number.MAX_VALUE - 4294967296 + 1) + 4294967296);
        // When
        const varInt1 = await bitcoin.data.getVarInt(num1);
        const varInt2 = await bitcoin.data.getVarInt(num2);
        const varInt3 = await bitcoin.data.getVarInt(num3);
        const varInt4 = await bitcoin.data.getVarInt(num4);
        // Then
        assert.strictEqual(num1, parseInt(varInt1, 16));
        assert.strictEqual('fd', varInt2.slice(0, 2));
        assert.strictEqual(num2, parseInt(await bitcoin.encode.reverseHex(varInt2.slice(2)), 16));
        assert.strictEqual('fe', varInt3.slice(0, 2));
        assert.strictEqual(num3, parseInt(await bitcoin.encode.reverseHex(varInt3.slice(2)), 16));
        assert.strictEqual('ff', varInt4.slice(0, 2));
        assert.strictEqual(num4, parseInt(await bitcoin.encode.reverseHex(varInt4.slice(2)), 16));
    });
});
describe('push data test', () => {
    it('push data encode for string', async () => {
        // Given
        const str = '';
        const num1 = Math.floor(Math.random() * (75 * 2 - 0 + 1) + 0);
        const num2 = Math.floor(Math.random() * (255 * 2 - 76 * 2 + 1) + 76 * 2);
        const num3 = Math.floor(Math.random() * (65535 * 2 - 256 * 2 + 1) + 256 * 2);
        const str1 = str.padStart(num1 % 2 === 0 ? num1 : num1 + 1, 'f');
        const str2 = str.padStart(num2 % 2 === 0 ? num2 : num2 + 1, 'f');
        const str3 = str.padStart(num3 % 2 === 0 ? num3 : num3 + 1, 'f');
        // When
        const pushData1 = await bitcoin.data.pushData(str1);
        const pushData2 = await bitcoin.data.pushData(str2);
        const pushData3 = await bitcoin.data.pushData(str3);
        // Then
        assert.strictEqual(parseInt(pushData1, 16) * 2, num1 % 2 === 0 ? num1 : num1 + 1);
        assert.strictEqual(pushData2.slice(0, 2), bitcoin.Opcode.OP_PUSHDATA1);
        assert.strictEqual(parseInt(pushData2.slice(2), 16) * 2, num2 % 2 === 0 ? num2 : num2 + 1);
        assert.strictEqual(pushData3.slice(0, 2), bitcoin.Opcode.OP_PUSHDATA2);
        assert.strictEqual(parseInt(pushData3.slice(4, 6) + pushData3.slice(2, 4), 16) * 2, num3 % 2 === 0 ? num3 : num3 + 1);
    });
});
