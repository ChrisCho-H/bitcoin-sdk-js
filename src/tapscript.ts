import { sha256 } from './crypto.js';
import { getVarInt } from './data.js';
import { bytesToHex, hexToBytes } from './encode.js';
import { secp256k1, schnorr } from '@noble/curves/secp256k1';

const tapLeafTagHex: string = '5461704c656166'; // 'TapLeaf' in UTF-8
const tapBranchTagHex: string = '5461704272616e6368'; // 'TapBranch' in UTF-8
const tapTweakTagHex: string = '546170547765616b'; // 'TapTweak' in UTF-8
const tapSighashTagHex: string = '54617053696768617368'; // 'TapSigHash' in UTF-8

interface TapTweakedPubkey {
  parityBit: '02' | '03';
  tweakedPubKey: string;
}

export const getTapLeaf = async (
  script: string,
  tapLeafVersion = 0xc0,
): Promise<Uint8Array> => {
  return await sha256(
    new Uint8Array([
      ...(await getTapTag(tapLeafTagHex)),
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
  // To do. compare hex in lexical
  const orderedTapPair: Uint8Array = new Uint8Array(
    BigInt('0x' + (await bytesToHex(tapLeafPair[0]))) <
    BigInt('0x' + (await bytesToHex(tapLeafPair[1])))
      ? [...tapLeafPair[0], ...tapLeafPair[1]]
      : [...tapLeafPair[1], ...tapLeafPair[0]],
  );
  return await sha256(
    new Uint8Array([...(await getTapTag(tapBranchTagHex)), ...orderedTapPair]),
  );
};

export const getTapTweak = async (
  schnorrPubkey: string,
  tapRoot: Uint8Array,
): Promise<Uint8Array> => {
  if (schnorrPubkey.length !== 64)
    throw new Error('Schnorr public key length must be 32 bytes hex');
  if (tapRoot.length !== 32) throw new Error('TapRoot must be 32 bytes hex');

  return await sha256(
    new Uint8Array([
      ...(await getTapTag(tapTweakTagHex)),
      ...(await hexToBytes(schnorrPubkey)),
      ...tapRoot,
    ]),
  );
};

export const getTapTag = async (tapTagHex: string): Promise<Uint8Array> => {
  const tapTagHash: Uint8Array = await sha256(await hexToBytes(tapTagHex));
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
    new Uint8Array([...(await getTapTag(tapSighashTagHex)), ...sigMsg]),
  );
};

export const getTapControlBlock = async (
  schnorrPubkey: string,
  tapLeaf: Uint8Array,
  tweakedPubKeyParityBit: '02' | '03',
  tapLeafVersion = 0xc0,
): Promise<string> => {
  tapLeafVersion += tweakedPubKeyParityBit === '02' ? 0x00 : 0x01;
  return (
    tapLeafVersion.toString(16) + schnorrPubkey + (await bytesToHex(tapLeaf))
  );
};
