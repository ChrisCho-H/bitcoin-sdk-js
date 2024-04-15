"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.getTapControlBlock = exports.getTapSigHash = exports.getTapTweakedPrivkey = exports.getTapTweakedPubkey = exports.getTapTag = exports.getTapTweak = exports.getTapBranch = exports.getTapLeaf = void 0;
const crypto_js_1 = require("./crypto.js");
const data_js_1 = require("./data.js");
const encode_js_1 = require("./encode.js");
const secp256k1_1 = require("@noble/curves/secp256k1");
const tapLeafTagBytes = new Uint8Array([
    84, 97, 112, 76, 101, 97, 102,
]); // 'TapLeaf' in UTF-8
const tapBranchTagBytes = new Uint8Array([
    84, 97, 112, 66, 114, 97, 110, 99, 104,
]); // 'TapBranch' in UTF-8
const tapTweakTagBytes = new Uint8Array([
    84, 97, 112, 84, 119, 101, 97, 107,
]); // 'TapTweak' in UTF-8
const tapSighashTagBytes = new Uint8Array([
    84, 97, 112, 83, 105, 103, 104, 97, 115, 104,
]); // 'TapSigHash' in UTF-8
const getTapLeaf = async (script, tapLeafVersion = 0xc0) => {
    return await (0, crypto_js_1.sha256)(new Uint8Array([
        ...(await (0, exports.getTapTag)(tapLeafTagBytes)),
        ...(await (0, encode_js_1.hexToBytes)(
        // make tap leaf version even
        (tapLeafVersion & 0xfe).toString(16) +
            (await (0, data_js_1.getVarInt)(script.length / 2)) +
            script)),
    ]));
};
exports.getTapLeaf = getTapLeaf;
const getTapBranch = async (tapLeafPair) => {
    if (tapLeafPair.length !== 2)
        throw new Error('TapLeaf pair length must be 2');
    if (tapLeafPair[0]?.length !== 32 || tapLeafPair[1]?.length !== 32)
        throw new Error('TapLeaf must be 32 bytes hex');
    // compare hex in lexical
    let mergedTapPair = new Uint8Array([...tapLeafPair[0], ...tapLeafPair[1]]);
    for (let i = 0; i < tapLeafPair[0]?.length; i++) {
        if (tapLeafPair[0][i] === tapLeafPair[1][i])
            continue;
        mergedTapPair = new Uint8Array(tapLeafPair[0][i] < tapLeafPair[1][i]
            ? [...tapLeafPair[0], ...tapLeafPair[1]]
            : [...tapLeafPair[1], ...tapLeafPair[0]]);
        break;
    }
    return await (0, crypto_js_1.sha256)(new Uint8Array([...(await (0, exports.getTapTag)(tapBranchTagBytes)), ...mergedTapPair]));
};
exports.getTapBranch = getTapBranch;
const getTapTweak = async (schnorrPubkey, taproot) => {
    if (schnorrPubkey.length !== 64)
        throw new Error('Schnorr public key length must be 32 bytes hex');
    if (taproot.length !== 32)
        throw new Error('TapRoot must be 32 bytes hex');
    return await (0, crypto_js_1.sha256)(new Uint8Array([
        ...(await (0, exports.getTapTag)(tapTweakTagBytes)),
        ...(await (0, encode_js_1.hexToBytes)(schnorrPubkey)),
        ...taproot,
    ]));
};
exports.getTapTweak = getTapTweak;
const getTapTag = async (tapTagBytes) => {
    const tapTagHash = await (0, crypto_js_1.sha256)(tapTagBytes);
    return new Uint8Array([...tapTagHash, ...tapTagHash]);
};
exports.getTapTag = getTapTag;
const getTapTweakedPubkey = async (schnorrPubkey, tapTweak) => {
    const P = secp256k1_1.schnorr.utils.lift_x(secp256k1_1.schnorr.utils.bytesToNumberBE(await (0, encode_js_1.hexToBytes)(schnorrPubkey)));
    const Q = P.add(secp256k1_1.secp256k1.ProjectivePoint.fromPrivateKey(tapTweak)); // Q = point_add(P, point_mul(G, t))
    return {
        parityBit: Q.hasEvenY() ? '02' : '03',
        tweakedPubKey: await (0, encode_js_1.bytesToHex)(new Uint8Array([...secp256k1_1.schnorr.utils.pointToBytes(Q)])),
    }; // bytes_from_int(x(Q))
};
exports.getTapTweakedPubkey = getTapTweakedPubkey;
const getTapTweakedPrivkey = async (schnorrPrivkey, tapTweak) => {
    const normal = secp256k1_1.secp256k1.utils.normPrivateKeyToScalar;
    const P = secp256k1_1.secp256k1.ProjectivePoint.fromPrivateKey(await (0, encode_js_1.hexToBytes)(schnorrPrivkey));
    return await (0, encode_js_1.bytesToHex)(secp256k1_1.schnorr.utils.numberToBytesBE(
    // private add
    secp256k1_1.schnorr.utils.mod(
    // private negate
    (P.hasEvenY() ? normal(schnorrPrivkey) : -normal(schnorrPrivkey)) +
        normal(tapTweak), secp256k1_1.secp256k1.CURVE.n), 32));
};
exports.getTapTweakedPrivkey = getTapTweakedPrivkey;
const getTapSigHash = async (sigMsg) => {
    return await (0, crypto_js_1.sha256)(new Uint8Array([...(await (0, exports.getTapTag)(tapSighashTagBytes)), ...sigMsg]));
};
exports.getTapSigHash = getTapSigHash;
const getTapControlBlock = async (schnorrPubkey, tapLeaf, tweakedPubKeyParityBit, tapLeafVersion = 0xc0) => {
    tapLeafVersion += tweakedPubKeyParityBit === '02' ? 0x00 : 0x01;
    return (tapLeafVersion.toString(16) + schnorrPubkey + (await (0, encode_js_1.bytesToHex)(tapLeaf)));
};
exports.getTapControlBlock = getTapControlBlock;
