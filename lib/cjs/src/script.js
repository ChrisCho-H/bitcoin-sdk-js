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
const data_js_1 = require("./data.js");
const encode_js_1 = require("./encode.js");
const validator_js_1 = require("./validator.js");
const getScriptByAddress = async (address) => {
    if (address.slice(0, 4) === 'bc1q' || address.slice(0, 4) === 'tb1q') {
        // segwit uses bech32
        const hash = (0, utils_1.bytesToHex)(new Uint8Array(bech32_1.bech32.fromWords(bech32_1.bech32.decode(address).words.slice(1))));
        return opcode_js_1.Opcode.OP_0 + (await (0, data_js_1.pushData)(hash)) + hash;
    }
    else if (address.slice(0, 4) === 'bc1p' || address.slice(0, 4) === 'tb1p') {
        const tapTweakedPubkey = (0, utils_1.bytesToHex)(new Uint8Array(bech32_1.bech32m.fromWords(bech32_1.bech32m.decode(address).words.slice(1))));
        // taproot is segwit v1
        return opcode_js_1.Opcode.OP_1 + (await (0, data_js_1.pushData)(tapTweakedPubkey)) + tapTweakedPubkey;
    }
    else {
        // legacy uses base58
        const hash = (0, utils_1.bytesToHex)(bs58_1.default.decode(address).slice(1, 21));
        if (address.slice(0, 1) === '3' || address.slice(0, 1) === '2') {
            // p2sh or p2wsh
            return (opcode_js_1.Opcode.OP_HASH160 +
                (await (0, data_js_1.pushData)(hash)) + // anything smaller than 4c is byte length to read
                hash +
                opcode_js_1.Opcode.OP_EQUAL);
        }
        else {
            // p2pkh default
            return (opcode_js_1.Opcode.OP_DUP +
                opcode_js_1.Opcode.OP_HASH160 +
                (await (0, data_js_1.pushData)(hash)) + // anything smaller than 4c is byte length to read
                hash +
                opcode_js_1.Opcode.OP_EQUALVERIFY +
                opcode_js_1.Opcode.OP_CHECKSIG);
        }
    }
};
exports.getScriptByAddress = getScriptByAddress;
const generateScriptHash = async (script, type = 'segwit') => {
    await validator_js_1.Validator.validateRedeemScript(script);
    const scriptByte = (0, utils_1.hexToBytes)(script);
    const scriptHash = type === 'segwit'
        ? await (0, crypto_js_1.sha256)(scriptByte) // sha256 for witness script
        : await (0, crypto_js_1.hash160)(scriptByte);
    return (0, utils_1.bytesToHex)(scriptHash);
};
exports.generateScriptHash = generateScriptHash;
const generateSingleSigScript = async (pubkey, type = 'segwit') => {
    if (type === 'taproot') {
        await validator_js_1.Validator.validateKeyPair(pubkey, '', 'schnorr');
        return (await (0, data_js_1.pushData)(pubkey)) + pubkey + opcode_js_1.Opcode.OP_CHECKSIG;
    }
    await validator_js_1.Validator.validateKeyPair(pubkey, '', 'ecdsa');
    const pubkeyHash = (0, utils_1.bytesToHex)(await (0, crypto_js_1.hash160)((0, utils_1.hexToBytes)(pubkey)));
    return (opcode_js_1.Opcode.OP_DUP +
        opcode_js_1.Opcode.OP_HASH160 +
        (await (0, data_js_1.pushData)(pubkeyHash)) + // anything smaller than 4c is byte length to read
        pubkeyHash +
        opcode_js_1.Opcode.OP_EQUALVERIFY +
        opcode_js_1.Opcode.OP_CHECKSIG);
};
exports.generateSingleSigScript = generateSingleSigScript;
const generateMultiSigScript = async (privkeyCount, pubkeys, type = 'segwit') => {
    if (privkeyCount <= 0 || pubkeys.length === 0)
        throw new Error('Both priv key and pub key count must be positive number');
    let multiSigScript = '';
    if (type !== 'taproot') {
        if (type === 'legacy' && (privkeyCount > 15 || pubkeys.length > 15))
            throw new Error('Maximum number of keys is 15');
        if (type === 'segwit' && (privkeyCount > 20 || pubkeys.length > 20))
            throw new Error('Maximum number of keys is 20');
        const pubkeyJoin = '21' + // first pubkey bytes to read
            pubkeys.join('21'); // other pubkey and bytes to read
        if (pubkeyJoin.length / pubkeys.length !== 68)
            throw new Error('pubkey must be compressed 33 bytes');
        // multi sig type of p2sh script
        multiSigScript +=
            (await (0, encode_js_1.scriptNum)(privkeyCount)) + // m signatures(OP_M)
                pubkeyJoin +
                (await (0, encode_js_1.scriptNum)(pubkeys.length)) + // n pubkeys(OP_N)
                opcode_js_1.Opcode.OP_CHECKMULTISIG;
    }
    else {
        if (privkeyCount > 999 || pubkeys.length > 999)
            throw new Error('Maximum number of keys is 999');
        pubkeys.forEach((v, i) => {
            if (v.length !== 64)
                throw new Error('pubkey must be compressed 32 bytes');
            multiSigScript +=
                '20' + // pubkey bytes to read(schnorr)
                    v +
                    (i === 0 ? opcode_js_1.Opcode.OP_CHECKSIG : opcode_js_1.Opcode.OP_CHECKSIGADD);
        }); // OP_CHECKSIGADD enabled for tapscript bip342
        // get priv count in hex
        const privkeyCountHex = await (0, encode_js_1.scriptNum)(privkeyCount);
        const dataToRead = privkeyCount <= 16 ? '' : await (0, data_js_1.pushData)(privkeyCountHex);
        // multi sig type of tapscript(OP_CHECKSIGADD)
        multiSigScript += dataToRead + privkeyCountHex + opcode_js_1.Opcode.OP_NUMEQUAL;
    }
    return multiSigScript;
};
exports.generateMultiSigScript = generateMultiSigScript;
const generateTimeLockScript = async (block) => {
    await validator_js_1.Validator.validateBlockLock(block);
    const locktime = await (0, encode_js_1.scriptNum)(block);
    const dataToRead = block <= 16 ? '' : await (0, data_js_1.pushData)(locktime);
    const opcode = opcode_js_1.Opcode.OP_CHECKLOCKTIMEVERIFY;
    return dataToRead + locktime + opcode + opcode_js_1.Opcode.OP_DROP;
};
exports.generateTimeLockScript = generateTimeLockScript;
const generateHashLockScript = async (secretHex) => {
    // if not even, pad 0 at last
    secretHex.length % 2 !== 0 ? (secretHex += '0') : '';
    await validator_js_1.Validator.validateScriptSig(secretHex);
    return (opcode_js_1.Opcode.OP_HASH256 +
        '20' + // hash256 always return 32 bytes
        (0, utils_1.bytesToHex)(await (0, crypto_js_1.hash256)((0, utils_1.hexToBytes)(secretHex))) +
        opcode_js_1.Opcode.OP_EQUALVERIFY // not OP_EQUAL to use with other script
    );
};
exports.generateHashLockScript = generateHashLockScript;
const generateDataScript = async (dataToWrite, encode = 'utf-8') => {
    const data = encode === 'hex' ? dataToWrite : (0, utils_1.bytesToHex)((0, utils_1.utf8ToBytes)(dataToWrite));
    if (data.length > 160)
        throw new Error('Maximum data size is 80 bytes');
    return opcode_js_1.Opcode.OP_RETURN + (await (0, data_js_1.pushData)(data)) + data;
};
exports.generateDataScript = generateDataScript;
