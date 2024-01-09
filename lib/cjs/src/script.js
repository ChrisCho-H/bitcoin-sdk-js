"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.generateDataScript = exports.generateHashLockScript = exports.generateTimeLockScript = exports.generateMultiSigScript = exports.generateSingleSigScript = exports.generateScriptHash = exports.getScriptByAddress = void 0;
const utils_1 = require("@noble/hashes/utils");
const bs58_1 = __importDefault(require("bs58"));
const bech32_1 = require("bech32");
const opcode_js_1 = require("./opcode.js");
const crypto_js_1 = require("./crypto.js");
const pushdata_js_1 = require("./pushdata.js");
const encode_js_1 = require("./encode.js");
const getScriptByAddress = async (address) => {
    if (address.slice(0, 4) === 'bc1q' || address.slice(0, 4) === 'tb1q') {
        // segwit uses bech32
        const hash = (0, utils_1.bytesToHex)(new Uint8Array(bech32_1.bech32.fromWords(bech32_1.bech32.decode(address).words.slice(1))));
        return opcode_js_1.Opcode.OP_0 + (await (0, pushdata_js_1.pushData)(hash)) + hash;
    }
    else {
        // legacy uses base58
        const hash = (0, utils_1.bytesToHex)(bs58_1.default.decode(address).slice(1, 21));
        if (address.slice(0, 1) === '3' || address.slice(0, 1) === '2') {
            // p2sh or p2wsh
            return (opcode_js_1.Opcode.OP_HASH160 +
                '14' + // anything smaller than 4c is byte length to read
                hash +
                opcode_js_1.Opcode.OP_EQUAL);
        }
        else {
            // p2pkh default
            return (opcode_js_1.Opcode.OP_DUP +
                opcode_js_1.Opcode.OP_HASH160 +
                '14' + // anything smaller than 4c is byte length to read
                hash +
                opcode_js_1.Opcode.OP_EQUALVERIFY +
                opcode_js_1.Opcode.OP_CHECKSIG);
        }
    }
};
exports.getScriptByAddress = getScriptByAddress;
const generateScriptHash = async (script, type = 'segwit') => {
    if (script.length > 1040 && type === 'legacy')
        throw new Error('Redeem script must be less than 520 bytes');
    if (script.length > 20000 && type === 'segwit')
        throw new Error('Witness script must be less than 10,000 bytes');
    const scriptByte = (0, utils_1.hexToBytes)(script);
    const scriptHash = type === 'segwit'
        ? await (0, crypto_js_1.sha256)(scriptByte) // sha256 for witness script
        : await (0, crypto_js_1.hash160)(scriptByte);
    return (0, utils_1.bytesToHex)(scriptHash);
};
exports.generateScriptHash = generateScriptHash;
const generateSingleSigScript = async (pubkey) => {
    if (pubkey.length !== 66)
        throw new Error('pubkey must be compressed 33 bytes');
    const pubkeyHash = (0, utils_1.bytesToHex)(await (0, crypto_js_1.hash160)((0, utils_1.hexToBytes)(pubkey)));
    return (opcode_js_1.Opcode.OP_DUP +
        opcode_js_1.Opcode.OP_HASH160 +
        '14' + // anything smaller than 4c is byte length to read
        pubkeyHash +
        opcode_js_1.Opcode.OP_EQUALVERIFY +
        opcode_js_1.Opcode.OP_CHECKSIG);
};
exports.generateSingleSigScript = generateSingleSigScript;
const generateMultiSigScript = async (privkeyCount, pubkeys) => {
    if (privkeyCount > 15 || pubkeys.length > 15)
        throw new Error('Maximum number of keys is 15');
    const pubkeyJoin = '21' + // first pubkey bytes to read
        pubkeys.join('21'); // other pubkey and bytes to read
    if (pubkeyJoin.length / pubkeys.length !== 68)
        throw new Error('pubkey must be compressed 33 bytes');
    // multi sig type of p2sh script
    const p2sh = (80 + privkeyCount).toString(16) + // m signatures
        pubkeyJoin +
        (80 + pubkeys.length).toString(16) + // n pubkeys
        opcode_js_1.Opcode.OP_CHECKMULTISIG;
    return p2sh;
};
exports.generateMultiSigScript = generateMultiSigScript;
const generateTimeLockScript = async (block) => {
    if (block >= 500000000)
        throw new Error('Block height must be < 500,000,000');
    let locktime = block.toString(16);
    locktime.length % 2 !== 0 ? (locktime = '0' + locktime) : '';
    const opcode = opcode_js_1.Opcode.OP_CHECKLOCKTIMEVERIFY;
    return ((await (0, pushdata_js_1.pushData)(locktime)) +
        (await (0, encode_js_1.reverseHex)(locktime)) +
        opcode +
        opcode_js_1.Opcode.OP_DROP);
};
exports.generateTimeLockScript = generateTimeLockScript;
const generateHashLockScript = async (secretHex) => {
    // if not even, pad 0 at last
    secretHex.length % 2 !== 0 ? (secretHex += '0') : '';
    if (secretHex.length > 3200)
        throw new Error('script sig must be less than 1650 bytes');
    return (opcode_js_1.Opcode.OP_HASH256 +
        '20' +
        (0, utils_1.bytesToHex)(await (0, crypto_js_1.hash256)((0, utils_1.hexToBytes)(secretHex))) +
        opcode_js_1.Opcode.OP_EQUALVERIFY // not OP_EQUAL to use with other script
    );
};
exports.generateHashLockScript = generateHashLockScript;
const generateDataScript = async (dataToWrite, encode = 'utf-8') => {
    const data = encode === 'hex' ? dataToWrite : (0, utils_1.bytesToHex)((0, utils_1.utf8ToBytes)(dataToWrite));
    if (data.length > 160)
        throw new Error('Maximum data size is 80 bytes');
    return opcode_js_1.Opcode.OP_RETURN + (await (0, pushdata_js_1.pushData)(data)) + data;
};
exports.generateDataScript = generateDataScript;
