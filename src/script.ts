import { hexToBytes, bytesToHex, utf8ToBytes } from '@noble/hashes/utils';
import bs58 from 'bs58';
import { bech32, bech32m } from 'bech32';
import { Opcode } from './opcode.js';
import { sha256, hash160, hash256 } from './crypto.js';
import { pushData } from './data.js';
import { reverseHex } from './encode.js';

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
        '14' + // anything smaller than 4c is byte length to read
        hash +
        Opcode.OP_EQUAL
      );
    } else {
      // p2pkh default
      return (
        Opcode.OP_DUP +
        Opcode.OP_HASH160 +
        '14' + // anything smaller than 4c is byte length to read
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
    throw new Error('Redeem script must be less than 520 bytes');
  if (script.length > 20000 && type === 'segwit')
    throw new Error('Witness script must be less than 10,000 bytes');
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
  if (type === 'taproot' && pubkey.length !== 64)
    throw new Error('schnorr pubkey must be tweaked 32 bytes');
  if (type === 'taproot') {
    return '20' + pubkey + Opcode.OP_CHECKSIG;
  }
  const pubkeyHash: string = bytesToHex(await hash160(hexToBytes(pubkey)));
  return (
    Opcode.OP_DUP +
    Opcode.OP_HASH160 +
    '14' + // anything smaller than 4c is byte length to read
    pubkeyHash +
    Opcode.OP_EQUALVERIFY +
    Opcode.OP_CHECKSIG
  );
};

export const generateMultiSigScript = async (
  privkeyCount: number,
  pubkeys: string[],
): Promise<string> => {
  if (privkeyCount > 15 || pubkeys.length > 15)
    throw new Error('Maximum number of keys is 15');

  const pubkeyJoin: string =
    '21' + // first pubkey bytes to read
    pubkeys.join('21'); // other pubkey and bytes to read
  if (pubkeyJoin.length / pubkeys.length !== 68)
    throw new Error('pubkey must be compressed 33 bytes');

  // multi sig type of p2sh script
  const p2sh: string =
    (80 + privkeyCount).toString(16) + // m signatures
    pubkeyJoin +
    (80 + pubkeys.length).toString(16) + // n pubkeys
    Opcode.OP_CHECKMULTISIG;
  return p2sh;
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
    '20' +
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
