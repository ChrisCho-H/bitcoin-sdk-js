import { sha256 } from './crypto.js';
import { getVarInt } from './data.js';
import { bytesToHex, hexToBytes } from './encode.js';
import { secp256k1, schnorr } from '@noble/curves/secp256k1';
import { Validator } from './validator.js';
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
export const getTapLeaf = async (script, tapLeafVersion = 0xc0) => {
    return await sha256(new Uint8Array([
        ...(await getTapTag(tapLeafTagBytes)),
        ...(await hexToBytes(
        // make tap leaf version even
        (tapLeafVersion & 0xfe).toString(16) +
            (await getVarInt(script.length / 2)) +
            script)),
    ]));
};
export const getTapBranch = async (tapLeafPair) => {
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
    return await sha256(new Uint8Array([...(await getTapTag(tapBranchTagBytes)), ...mergedTapPair]));
};
export const getTapTweak = async (schnorrPubkey, taproot) => {
    await Validator.validateKeyPair(schnorrPubkey, '', 'schnorr');
    if (taproot && taproot.length !== 32)
        throw new Error('TapRoot must be 32 bytes');
    const tweakPubOnly = new Uint8Array([
        ...(await getTapTag(tapTweakTagBytes)),
        ...(await hexToBytes(schnorrPubkey)),
    ]);
    return await sha256(!taproot ? tweakPubOnly : new Uint8Array([...tweakPubOnly, ...taproot]));
};
export const getTapTag = async (tapTagBytes) => {
    const tapTagHash = await sha256(tapTagBytes);
    return new Uint8Array([...tapTagHash, ...tapTagHash]);
};
export const getTapTweakedPubkey = async (schnorrPubkey, tapTweak) => {
    await Validator.validateKeyPair(schnorrPubkey, '', 'schnorr');
    const P = schnorr.utils.lift_x(schnorr.utils.bytesToNumberBE(await hexToBytes(schnorrPubkey)));
    const Q = P.add(secp256k1.ProjectivePoint.fromPrivateKey(tapTweak)); // Q = point_add(P, point_mul(G, t))
    return {
        parityBit: Q.hasEvenY() ? '02' : '03',
        tweakedPubKey: await bytesToHex(new Uint8Array([...schnorr.utils.pointToBytes(Q)])),
    }; // bytes_from_int(x(Q))
};
export const getTapTweakedPrivkey = async (schnorrPrivkey, tapTweak) => {
    await Validator.validateKeyPair('', schnorrPrivkey, 'schnorr');
    const normal = secp256k1.utils.normPrivateKeyToScalar;
    const P = secp256k1.ProjectivePoint.fromPrivateKey(await hexToBytes(schnorrPrivkey));
    return await bytesToHex(schnorr.utils.numberToBytesBE(
    // private add
    schnorr.utils.mod(
    // private negate
    (P.hasEvenY() ? normal(schnorrPrivkey) : -normal(schnorrPrivkey)) +
        normal(tapTweak), secp256k1.CURVE.n), 32));
};
export const getTapSigHash = async (sigMsg) => {
    return await sha256(new Uint8Array([...(await getTapTag(tapSighashTagBytes)), ...sigMsg]));
};
export const getTapControlBlock = async (schnorrPubkey, tweakedPubKeyParityBit, tapTreePath, tapLeafVersion = 0xc0) => {
    await Validator.validateKeyPair(schnorrPubkey, '', 'schnorr');
    tapLeafVersion += tweakedPubKeyParityBit === '02' ? 0x00 : 0x01;
    return (tapLeafVersion.toString(16) +
        schnorrPubkey +
        (await bytesToHex(tapTreePath)));
};
