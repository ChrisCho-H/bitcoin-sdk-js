"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.getTapSigHash = exports.getTapTweakedPrivkey = exports.getTapTweakedPubkey = exports.getTapTag = exports.getTapTweak = exports.getTapBranch = exports.getTapLeaf = void 0;
const crypto_js_1 = require("./crypto.js");
const data_js_1 = require("./data.js");
const encode_js_1 = require("./encode.js");
const secp256k1_1 = require("@noble/curves/secp256k1");
const tapLeafTagHex = '5461704c656166'; // 'TapLeaf' in UTF-8
const tapBranchTagHex = '5461704272616e6368'; // 'TapBranch' in UTF-8
const tapTweakTagHex = '546170547765616b'; // 'TapTweak' in UTF-8
const tapSighashTagHex = '54617053696768617368'; // 'TapSigHash' in UTF-8
const version = 0xc0 & 0xfe;
const getTapLeaf = async (script) => {
    return await (0, crypto_js_1.sha256)(new Uint8Array([
        ...(await (0, exports.getTapTag)(tapLeafTagHex)),
        ...(await (0, encode_js_1.hexToBytes)(version.toString(16) + (await (0, data_js_1.getVarInt)(script.length / 2)) + script)),
    ]));
};
exports.getTapLeaf = getTapLeaf;
const getTapBranch = async (tapLeafPair) => {
    if (tapLeafPair.length !== 2)
        throw new Error('TapLeaf pair length must be 2');
    if (tapLeafPair[0]?.length !== 32 || tapLeafPair[1]?.length !== 32)
        throw new Error('TapLeaf must be 32 bytes hex');
    // To do. compare hex in lexical
    const orderedTapPair = new Uint8Array(BigInt('0x' + (await (0, encode_js_1.bytesToHex)(tapLeafPair[0]))) <
        BigInt('0x' + (await (0, encode_js_1.bytesToHex)(tapLeafPair[1])))
        ? [...tapLeafPair[0], ...tapLeafPair[1]]
        : [...tapLeafPair[1], ...tapLeafPair[0]]);
    return await (0, crypto_js_1.sha256)(new Uint8Array([...(await (0, exports.getTapTag)(tapBranchTagHex)), ...orderedTapPair]));
};
exports.getTapBranch = getTapBranch;
const getTapTweak = async (schnorrPubkey, tapRoot) => {
    if (schnorrPubkey.length !== 64)
        throw new Error('Schnorr public key length must be 32 bytes hex');
    if (tapRoot.length !== 32)
        throw new Error('TapRoot must be 32 bytes hex');
    return await (0, crypto_js_1.sha256)(new Uint8Array([
        ...(await (0, exports.getTapTag)(tapTweakTagHex)),
        ...(await (0, encode_js_1.hexToBytes)(schnorrPubkey)),
        ...tapRoot,
    ]));
};
exports.getTapTweak = getTapTweak;
const getTapTag = async (tapTagHex) => {
    const tapTagHash = await (0, crypto_js_1.sha256)(await (0, encode_js_1.hexToBytes)(tapTagHex));
    return new Uint8Array([...tapTagHash, ...tapTagHash]);
};
exports.getTapTag = getTapTag;
const getTapTweakedPubkey = async (schnorrPubkey, tapTweak) => {
    const P = secp256k1_1.schnorr.utils.lift_x(secp256k1_1.schnorr.utils.bytesToNumberBE(await (0, encode_js_1.hexToBytes)(schnorrPubkey)));
    const Q = P.add(secp256k1_1.secp256k1.ProjectivePoint.fromPrivateKey(tapTweak)); // Q = point_add(P, point_mul(G, t))
    return await (0, encode_js_1.bytesToHex)(new Uint8Array([
        // Q.hasEvenY() ? 2 : 3,
        ...secp256k1_1.schnorr.utils.pointToBytes(Q),
    ])); // bytes_from_int(x(Q))
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
    return await (0, crypto_js_1.sha256)(new Uint8Array([...(await (0, exports.getTapTag)(tapSighashTagHex)), ...sigMsg]));
};
exports.getTapSigHash = getTapSigHash;
