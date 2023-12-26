import { hexToBytes, bytesToHex, utf8ToBytes } from '@noble/hashes/utils';
import bs58 from 'bs58';
import { Opcode } from './opcode.js';
import { sha256, hash160, hash256 } from './crypto.js';
import { pushData } from './pushdata.js';
import { reverseHex } from './encode.js';

export const getScriptByAddress = async (address: string): Promise<string> => {
  if (
    address.slice(0, 1) === '9' ||
    address.slice(0, 1) === 'A' ||
    address.slice(0, 1) === '2'
  ) {
    return (
      Opcode.OP_HASH160 +
      '14' + // anything smaller than 4c is byte length to read
      bytesToHex(bs58.decode(address).slice(1, 21)) +
      Opcode.OP_EQUAL
    );
  } else {
    // p2pkh default
    return (
      Opcode.OP_DUP +
      Opcode.OP_HASH160 +
      '14' + // anything smaller than 4c is byte length to read
      bytesToHex(bs58.decode(address).slice(1, 21)) +
      Opcode.OP_EQUALVERIFY +
      Opcode.OP_CHECKSIG
    );
  }
};

export const generateScriptHash = async (
  script: string,
  isSegWit = true,
): Promise<string> => {
  if (script.length > 1040 && !isSegWit)
    throw new Error('Redeem script must be less than 520 bytes');
  const scriptByte: Uint8Array = hexToBytes(script);
  const scriptHash: Uint8Array = isSegWit
    ? await sha256(scriptByte) // sha256 for witness script
    : await hash160(scriptByte);
  return bytesToHex(scriptHash);
};

export const generateSingleSigScript = async (
  pubkey: string,
): Promise<string> => {
  if (pubkey.length !== 66)
    throw new Error('pubkey must be compressed 33 bytes');
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
  block?: number,
  utc?: number,
  isAbsolute = true,
): Promise<string> => {
  if (!block && !utc)
    throw new Error('Either block or utc must be given for output');
  if (isAbsolute) {
    if (block && block >= 500000000)
      throw new Error('Block height must be < 500,000,000');
    if (utc && utc < 500000000) throw new Error('UTC must be >= 500,000,000');
  } else {
    if (block && block > 65535)
      throw new Error('Block height must be < 65,535');
    if (utc && utc > 33554430) throw new Error('UTC must be < 33,554,431');
    if (utc && utc % 512 !== 0) throw new Error('UTC must be mutiple of 512');
  }

  let locktime: string = block
    ? block.toString(16)
    : (utc as number).toString(16);
  locktime.length % 2 !== 0 ? (locktime = '0' + locktime) : '';
  const opcode: string = isAbsolute
    ? Opcode.OP_CHECKLOCKTIMEVERIFY
    : Opcode.OP_CHECKSEQUENCEVERIFY;
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
    Opcode.OP_EQUAL
  );
};

export const generateDataScript = async (
  dataToWrite: string,
  encode?: 'utf-8' | 'hex',
): Promise<string> => {
  const data: string =
    encode === 'hex' ? dataToWrite : bytesToHex(utf8ToBytes(dataToWrite));
  if (data.length > 160) throw new Error('Maximum data size is 80 bytes');
  return Opcode.OP_RETURN + (await pushData(data)) + data;
};
