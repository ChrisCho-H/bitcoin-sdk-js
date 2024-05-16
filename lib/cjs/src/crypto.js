"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.verifyMessage = exports.signMessage = exports.verify = exports.sign = exports.sha256 = exports.ripemd160 = exports.hash256 = exports.hash160 = void 0;
const ripemd160_1 = require("@noble/hashes/ripemd160");
const sha256_1 = require("@noble/hashes/sha256");
const secp256k1_1 = require("@noble/curves/secp256k1");
const encode_js_1 = require("./encode.js");
const validator_js_1 = require("./validator.js");
const data_js_1 = require("./data.js");
const script_js_1 = require("./script.js");
const opcode_js_1 = require("./opcode.js");
const transaction_js_1 = require("./transaction.js");
const tapscript_js_1 = require("./tapscript.js");
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
const signMessage = async (msg, privkey, address) => {
    const script = await (0, script_js_1.getScriptByAddress)(address);
    // legacy p2pkh adress use legacy signing process
    if (script.slice(0, 2) === opcode_js_1.Opcode.OP_DUP) {
        const prefix = await (0, encode_js_1.utf8ToBytes)('\x18Bitcoin Signed Message:\n');
        const msgHex = await (0, encode_js_1.utf8ToBytes)(msg);
        const len = await (0, data_js_1.getVarInt)(msgHex.length);
        const msgHash = await (0, exports.hash256)(new Uint8Array([...prefix, ...(await (0, encode_js_1.hexToBytes)(len)), ...msgHex]));
        const sig = secp256k1_1.secp256k1.sign(msgHash, privkey);
        return (0, encode_js_1.bytesToBase64)(new Uint8Array([sig.recovery + 31, ...sig.toCompactRawBytes()]));
    }
    else {
        const pubkey = await (0, encode_js_1.bytesToHex)(secp256k1_1.secp256k1.getPublicKey(privkey));
        const txToSign = await _getVirtualTx(msg, script);
        // segwit p2wpkh and taproot p2tr use bip322 signing processs
        if (script.slice(0, 2) === opcode_js_1.Opcode.OP_0) {
            await txToSign.signInput(pubkey, privkey, 0);
        }
        else if (script.slice(0, 2) === opcode_js_1.Opcode.OP_1) {
            const tapTweak = await (0, tapscript_js_1.getTapTweak)(pubkey.slice(2));
            const tweakedPrivKey = await (0, tapscript_js_1.getTapTweakedPrivkey)(privkey, tapTweak);
            await txToSign.signInput('', tweakedPrivKey, 0, 'taproot', '', '', '01_TRICK_SIGHASH_ALL');
        }
        else {
            throw new Error('Only p2pkh, p2wpkh, p2tr address are supported now');
        }
        // return private witness field
        return (0, encode_js_1.bytesToBase64)(await (0, encode_js_1.hexToBytes)(txToSign._witness.get(0)));
    }
};
exports.signMessage = signMessage;
const verifyMessage = async (msg, signature, address) => {
    const signatureHex = await (0, encode_js_1.bytesToHex)(await (0, encode_js_1.base64ToBytes)(signature));
    const script = await (0, script_js_1.getScriptByAddress)(address);
    // legacy p2pkh adress use legacy verifying process
    if (script.slice(0, 2) === opcode_js_1.Opcode.OP_DUP) {
        const prefix = await (0, encode_js_1.utf8ToBytes)('\x18Bitcoin Signed Message:\n');
        const msgHex = await (0, encode_js_1.utf8ToBytes)(msg);
        const len = await (0, data_js_1.getVarInt)(msgHex.length);
        const msgHash = await (0, exports.hash256)(new Uint8Array([...prefix, ...(await (0, encode_js_1.hexToBytes)(len)), ...msgHex]));
        const pubkeyHash = script.slice(6, 6 + 40);
        const pubkey = secp256k1_1.secp256k1.Signature.fromCompact(signatureHex.slice(2))
            .addRecoveryBit(parseInt(signatureHex.slice(0, 2), 16) - 0x1f)
            .recoverPublicKey(msgHash)
            .toRawBytes();
        return (await (0, encode_js_1.bytesToHex)(await (0, exports.hash160)(pubkey))) === pubkeyHash;
    }
    else {
        const txToSign = await _getVirtualTx(msg, script);
        // segwit p2wpkh and taproot p2tr use bip322 signing processs
        if (script.slice(0, 2) === opcode_js_1.Opcode.OP_0) {
            const sigLen = parseInt(signatureHex.slice(2, 4), 16) * 2;
            const sig = signatureHex.slice(4, 4 + sigLen - 2); // remove sighash_type, varint
            const pubkey = signatureHex.slice(6 + sigLen); // remove varint
            const scriptCode = await (0, script_js_1.generateSingleSigScript)(pubkey);
            const msgHash = await txToSign.getInputHashToSign(scriptCode, 0, 'segwit');
            return secp256k1_1.secp256k1.verify(sig, msgHash, pubkey);
        }
        else if (script.slice(0, 2) === opcode_js_1.Opcode.OP_1) {
            const sig = signatureHex.slice(4, 132);
            const pubkey = script.slice(4);
            const msgHash = await txToSign.getInputHashToSign('', 0, 'taproot', '01_TRICK_SIGHASH_ALL');
            return secp256k1_1.schnorr.verify(sig, msgHash, pubkey);
        }
        throw new Error('Only p2pkh, p2wpkh, p2tr address are supported now');
    }
};
exports.verifyMessage = verifyMessage;
const _getVirtualTx = async (msg, script) => {
    // build tx to spend
    const txToSpend = new transaction_js_1.Transaction();
    await txToSpend.setVersion(0);
    await txToSpend.addInput({
        txHash: await (0, encode_js_1.padZeroHexN)('', 64),
        index: 0xffffffff,
        value: 0,
        sequence: '00000000',
    });
    await txToSpend.addOutput({
        script: script,
        value: 0,
    });
    const msgHash = await (0, encode_js_1.bytesToHex)(await (0, exports.sha256)(new Uint8Array([
        ...(await (0, tapscript_js_1.getTapTag)(await (0, encode_js_1.utf8ToBytes)('BIP0322-signed-message'))),
        ...(await (0, encode_js_1.utf8ToBytes)(msg)),
    ])));
    await txToSpend.signInputByScriptSig(['', msgHash], // OP_0 PUSH32[ message_hash ]
    0, 'legacy');
    // build tx to sign
    const txToSign = new transaction_js_1.Transaction();
    await txToSign.setVersion(0);
    await txToSign.addInput({
        txHash: await txToSpend.getId(),
        index: 0,
        value: 0,
        sequence: '00000000',
        script: script,
    });
    await txToSign.addOutput({
        script: opcode_js_1.Opcode.OP_RETURN,
        value: 0,
    });
    return txToSign;
};
