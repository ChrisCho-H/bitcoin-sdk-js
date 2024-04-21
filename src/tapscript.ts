import { sha256 } from './crypto.js';
import { getVarInt } from './data.js';
import { bytesToHex, hexToBytes } from './encode.js';
import { secp256k1, schnorr } from '@noble/curves/secp256k1';

const tapLeafTagBytes: Uint8Array = new Uint8Array([
  84, 97, 112, 76, 101, 97, 102,
]); // 'TapLeaf' in UTF-8
const tapBranchTagBytes: Uint8Array = new Uint8Array([
  84, 97, 112, 66, 114, 97, 110, 99, 104,
]); // 'TapBranch' in UTF-8
const tapTweakTagBytes: Uint8Array = new Uint8Array([
  84, 97, 112, 84, 119, 101, 97, 107,
]); // 'TapTweak' in UTF-8
const tapSighashTagBytes: Uint8Array = new Uint8Array([
  84, 97, 112, 83, 105, 103, 104, 97, 115, 104,
]); // 'TapSigHash' in UTF-8

export interface TapTweakedPubkey {
  parityBit: '02' | '03';
  tweakedPubKey: string;
}

export const getTapLeaf = async (
  script: string,
  tapLeafVersion = 0xc0,
): Promise<Uint8Array> => {
  return await sha256(
    new Uint8Array([
      ...(await getTapTag(tapLeafTagBytes)),
      ...(await hexToBytes(
        // make tap leaf version even
        (tapLeafVersion & 0xfe).toString(16) +
          (await getVarInt(script.length / 2)) +
          script,
      )),
    ]),
  );
};

export const getTapBranch = async (
  tapLeafPair: Uint8Array[],
): Promise<Uint8Array> => {
  if (tapLeafPair.length !== 2)
    throw new Error('TapLeaf pair length must be 2');
  if (tapLeafPair[0]?.length !== 32 || tapLeafPair[1]?.length !== 32)
    throw new Error('TapLeaf must be 32 bytes hex');
  // compare hex in lexical
  let mergedTapPair = new Uint8Array([...tapLeafPair[0], ...tapLeafPair[1]]);
  for (let i: number = 0; i < tapLeafPair[0]?.length; i++) {
    if (tapLeafPair[0][i] === tapLeafPair[1][i]) continue;
    mergedTapPair = new Uint8Array(
      tapLeafPair[0][i] < tapLeafPair[1][i]
        ? [...tapLeafPair[0], ...tapLeafPair[1]]
        : [...tapLeafPair[1], ...tapLeafPair[0]],
    );
    break;
  }
  return await sha256(
    new Uint8Array([...(await getTapTag(tapBranchTagBytes)), ...mergedTapPair]),
  );
};

export const getTapTweak = async (
  schnorrPubkey: string,
  taproot: Uint8Array,
): Promise<Uint8Array> => {
  if (schnorrPubkey.length !== 64)
    throw new Error('Schnorr public key length must be 32 bytes hex');
  if (taproot.length !== 32) throw new Error('TapRoot must be 32 bytes hex');

  return await sha256(
    new Uint8Array([
      ...(await getTapTag(tapTweakTagBytes)),
      ...(await hexToBytes(schnorrPubkey)),
      ...taproot,
    ]),
  );
};

export const getTapTag = async (
  tapTagBytes: Uint8Array,
): Promise<Uint8Array> => {
  const tapTagHash: Uint8Array = await sha256(tapTagBytes);
  return new Uint8Array([...tapTagHash, ...tapTagHash]);
};

export const getTapTweakedPubkey = async (
  schnorrPubkey: string,
  tapTweak: Uint8Array,
): Promise<TapTweakedPubkey> => {
  const P = schnorr.utils.lift_x(
    schnorr.utils.bytesToNumberBE(await hexToBytes(schnorrPubkey)),
  );
  const Q = P.add(secp256k1.ProjectivePoint.fromPrivateKey(tapTweak)); // Q = point_add(P, point_mul(G, t))
  return {
    parityBit: Q.hasEvenY() ? '02' : '03',
    tweakedPubKey: await bytesToHex(
      new Uint8Array([...schnorr.utils.pointToBytes(Q)]),
    ),
  }; // bytes_from_int(x(Q))
};

export const getTapTweakedPrivkey = async (
  schnorrPrivkey: string,
  tapTweak: Uint8Array,
): Promise<string> => {
  const normal = secp256k1.utils.normPrivateKeyToScalar;

  const P = secp256k1.ProjectivePoint.fromPrivateKey(
    await hexToBytes(schnorrPrivkey),
  );

  return await bytesToHex(
    schnorr.utils.numberToBytesBE(
      // private add
      schnorr.utils.mod(
        // private negate
        (P.hasEvenY() ? normal(schnorrPrivkey) : -normal(schnorrPrivkey)) +
          normal(tapTweak),
        secp256k1.CURVE.n,
      ),
      32,
    ),
  );
};

export const getTapSigHash = async (
  sigMsg: Uint8Array,
): Promise<Uint8Array> => {
  return await sha256(
    new Uint8Array([...(await getTapTag(tapSighashTagBytes)), ...sigMsg]),
  );
};

export const getTapControlBlock = async (
  schnorrPubkey: string,
  tweakedPubKeyParityBit: '02' | '03',
  tapTreePath: Uint8Array,
  tapLeafVersion = 0xc0,
): Promise<string> => {
  tapLeafVersion += tweakedPubKeyParityBit === '02' ? 0x00 : 0x01;
  return (
    tapLeafVersion.toString(16) + schnorrPubkey + (await bytesToHex(tapTreePath))
  );
};
