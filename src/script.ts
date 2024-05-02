import { hexToBytes, bytesToHex, utf8ToBytes } from '@noble/hashes/utils';
import bs58 from 'bs58';
import { bech32, bech32m } from 'bech32';
import { Opcode } from './opcode.js';
import { sha256, hash160, hash256 } from './crypto.js';
import { pushData } from './data.js';
import { padZeroHexN, reverseHex } from './encode.js';

export const getScriptByAddress = async (address: string): Promise<string> => {
  if (address.slice(0, 4) === 'bc1q' || address.slice(0, 4) === 'tb1q') {
    // segwit uses bech32
    const hash: string = bytesToHex(
      new Uint8Array(bech32.fromWords(bech32.decode(address).words.slice(1))),
    );
    return Opcode.OP_0 + (await pushData(hash)) + hash;
  } else if (address.slice(0, 4) === 'bc1p' || address.slice(0, 4) === 'tb1p') {
    const tapTweakedPubkey: string = bytesToHex(
      new Uint8Array(bech32m.fromWords(bech32m.decode(address).words.slice(1))),
    );
    // taproot is segwit v1
    return Opcode.OP_1 + (await pushData(tapTweakedPubkey)) + tapTweakedPubkey;
  } else {
    // legacy uses base58
    const hash: string = bytesToHex(bs58.decode(address).slice(1, 21));
    if (address.slice(0, 1) === '3' || address.slice(0, 1) === '2') {
      // p2sh or p2wsh
      return (
        Opcode.OP_HASH160 +
        (await pushData(hash)) + // anything smaller than 4c is byte length to read
        hash +
        Opcode.OP_EQUAL
      );
    } else {
      // p2pkh default
      return (
        Opcode.OP_DUP +
        Opcode.OP_HASH160 +
        (await pushData(hash)) + // anything smaller than 4c is byte length to read
        hash +
        Opcode.OP_EQUALVERIFY +
        Opcode.OP_CHECKSIG
      );
    }
  }
};

export const generateScriptHash = async (
  script: string,
  type: 'legacy' | 'segwit' = 'segwit',
): Promise<string> => {
  if (script.length > 1040 && type === 'legacy')
    throw new Error('Redeem script must be equal or less than 520 bytes');
  if (script.length > 7200 && type === 'segwit')
    throw new Error('Witness script must be equal or less than 3,600 bytes');
  const scriptByte: Uint8Array = hexToBytes(script);
  const scriptHash: Uint8Array =
    type === 'segwit'
      ? await sha256(scriptByte) // sha256 for witness script
      : await hash160(scriptByte);
  return bytesToHex(scriptHash);
};

export const generateSingleSigScript = async (
  pubkey: string,
  type: 'legacy' | 'segwit' | 'taproot' = 'segwit',
): Promise<string> => {
  if (type !== 'taproot' && pubkey.length !== 66)
    throw new Error('pubkey must be compressed 33 bytes');
  if (type === 'taproot') {
    if (pubkey.length !== 64)
      throw new Error('schnorr pubkey must be tweaked 32 bytes');
    return (await pushData(pubkey)) + pubkey + Opcode.OP_CHECKSIG;
  }
  const pubkeyHash: string = bytesToHex(await hash160(hexToBytes(pubkey)));
  return (
    Opcode.OP_DUP +
    Opcode.OP_HASH160 +
    (await pushData(pubkeyHash)) + // anything smaller than 4c is byte length to read
    pubkeyHash +
    Opcode.OP_EQUALVERIFY +
    Opcode.OP_CHECKSIG
  );
};

export const generateMultiSigScript = async (
  privkeyCount: number,
  pubkeys: string[],
  type: 'segwit' | 'taproot' = 'segwit',
): Promise<string> => {
  let multiSigScript: string = '';
  if (type === 'segwit') {
    if (privkeyCount > 15 || pubkeys.length > 15)
      throw new Error('Maximum number of keys is 15');

    const pubkeyJoin: string =
      '21' + // first pubkey bytes to read
      pubkeys.join('21'); // other pubkey and bytes to read
    if (pubkeyJoin.length / pubkeys.length !== 68)
      throw new Error('pubkey must be compressed 33 bytes');

    // multi sig type of p2sh script
    multiSigScript +=
      (0x50 + privkeyCount).toString(16) + // m signatures(OP_M)
      pubkeyJoin +
      (0x50 + pubkeys.length).toString(16) + // n pubkeys(OP_N)
      Opcode.OP_CHECKMULTISIG;
  } else if (type === 'taproot') {
    if (privkeyCount > 999 || pubkeys.length > 999)
      throw new Error('Maximum number of keys is 999');

    pubkeys.forEach((v, i) => {
      if (v.length !== 64)
        throw new Error('pubkey must be compressed 32 bytes');
      multiSigScript +=
        '20' + // pubkey bytes to read(schnorr)
        v +
        (i === 0 ? Opcode.OP_CHECKSIG : Opcode.OP_CHECKSIGADD);
    }); // OP_CHECKSIGADD enabled for tapscript bip342

    // get priv count in hex
    let privkeyCountHex: string = privkeyCount.toString(16);
    privkeyCountHex = await padZeroHexN(
      privkeyCountHex,
      privkeyCountHex.length < 3 ? 2 : 4,
    );

    // multi sig type of tapscript(OP_CHECKSIGADD)
    multiSigScript +=
      (await pushData(privkeyCountHex)) +
      privkeyCountHex +
      Opcode.OP_GREATERTHANOREQUAL;
  } else {
    throw new Error('type must be either segwit or taproot');
  }
  return multiSigScript;
};

export const generateTimeLockScript = async (
  block: number,
): Promise<string> => {
  if (block >= 500000000) throw new Error('Block height must be < 500,000,000');

  let locktime: string = block.toString(16);
  locktime.length % 2 !== 0 ? (locktime = '0' + locktime) : '';
  const opcode: string = Opcode.OP_CHECKLOCKTIMEVERIFY;
  return (
    (await pushData(locktime)) +
    (await reverseHex(locktime)) +
    opcode +
    Opcode.OP_DROP
  );
};

export const generateHashLockScript = async (
  secretHex: string,
): Promise<string> => {
  // if not even, pad 0 at last
  secretHex.length % 2 !== 0 ? (secretHex += '0') : '';
  if (secretHex.length > 3200)
    throw new Error('script sig must be less than 1650 bytes');

  return (
    Opcode.OP_HASH256 +
    '20' + // hash256 always return 32 bytes
    bytesToHex(await hash256(hexToBytes(secretHex))) +
    Opcode.OP_EQUALVERIFY // not OP_EQUAL to use with other script
  );
};

export const generateDataScript = async (
  dataToWrite: string,
  encode: 'utf-8' | 'hex' = 'utf-8',
): Promise<string> => {
  const data: string =
    encode === 'hex' ? dataToWrite : bytesToHex(utf8ToBytes(dataToWrite));
  if (data.length > 160) throw new Error('Maximum data size is 80 bytes');
  return Opcode.OP_RETURN + (await pushData(data)) + data;
};
