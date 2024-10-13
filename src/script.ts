import { hexToBytes, bytesToHex, utf8ToBytes } from '@noble/hashes/utils';
import bs58 from 'bs58';
import { bech32, bech32m } from 'bech32';
import { Opcode } from './opcode.js';
import { sha256, hash160, hash256 } from './crypto.js';
import { pushData } from './data.js';
import { scriptNum } from './encode.js';
import { Validator } from './validator.js';

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
  await Validator.validateRedeemScript(script);

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
  if (type === 'taproot') {
    await Validator.validateKeyPair(pubkey, '', 'schnorr');
    return (await pushData(pubkey)) + pubkey + Opcode.OP_CHECKSIG;
  }

  await Validator.validateKeyPair(pubkey, '', 'ecdsa');
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
  type: 'legacy' | 'segwit' | 'taproot' = 'segwit',
): Promise<string> => {
  if (privkeyCount <= 0 || pubkeys.length === 0)
    throw new Error('Both priv key and pub key count must be positive number');
  let multiSigScript: string = '';
  if (type !== 'taproot') {
    if (type === 'legacy' && (privkeyCount > 15 || pubkeys.length > 15))
      throw new Error('Maximum number of keys is 15');
    if (type === 'segwit' && (privkeyCount > 20 || pubkeys.length > 20))
      throw new Error('Maximum number of keys is 20');

    const pubkeyJoin: string =
      '21' + // first pubkey bytes to read
      pubkeys.join('21'); // other pubkey and bytes to read
    if (pubkeyJoin.length / pubkeys.length !== 68)
      throw new Error('pubkey must be compressed 33 bytes');

    // multi sig type of p2sh script
    multiSigScript +=
      (await scriptNum(privkeyCount)) + // m signatures(OP_M)
      pubkeyJoin +
      (await scriptNum(pubkeys.length)) + // n pubkeys(OP_N)
      Opcode.OP_CHECKMULTISIG;
  } else {
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
    const privkeyCountHex: string = await scriptNum(privkeyCount);
    const dataToRead: string =
      privkeyCount <= 16 ? '' : await pushData(privkeyCountHex);

    // multi sig type of tapscript(OP_CHECKSIGADD)
    multiSigScript += dataToRead + privkeyCountHex + Opcode.OP_NUMEQUAL;
  }
  return multiSigScript;
};

export const generateTimeLockScript = async (
  block: number,
): Promise<string> => {
  await Validator.validateBlockLock(block);

  const locktime: string = await scriptNum(block);
  const dataToRead: string = block <= 16 ? '' : await pushData(locktime);

  const opcode: string = Opcode.OP_CHECKLOCKTIMEVERIFY;
  return dataToRead + locktime + opcode + Opcode.OP_DROP;
};

export const generateHashLockScript = async (
  secretHex: string,
): Promise<string> => {
  // if not even, pad 0 at last
  secretHex.length % 2 !== 0 ? (secretHex += '0') : '';
  await Validator.validateScriptSig(secretHex);

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
