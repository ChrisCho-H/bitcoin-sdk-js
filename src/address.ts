import { hexToBytes } from '@noble/hashes/utils';
import bs58 from 'bs58';
import { hash160, hash256, sha256 } from './crypto.js';
import { bech32, bech32m } from 'bech32';
import { Validator } from './validator.js';

export const generateAddress = async (
  pubkey: string,
  type: 'legacy' | 'segwit' | 'taproot' = 'segwit',
  network: 'mainnet' | 'testnet' = 'mainnet',
): Promise<string> => {
  await Validator.validateKeyPair(
    pubkey,
    '',
    type === 'taproot' ? 'schnorr' : 'ecdsa',
  );

  if (type === 'taproot') {
    const words: number[] = bech32m.toWords(hexToBytes(pubkey));
    words.unshift(1); // taproot is segwit version 1
    return bech32m.encode(network === 'mainnet' ? 'bc' : 'tb', words);
  }

  const pubkeyHash: Uint8Array = await hash160(hexToBytes(pubkey));
  if (type === 'segwit') {
    const words: number[] = bech32.toWords(pubkeyHash);
    words.unshift(0); // segwit version
    return bech32.encode(network === 'mainnet' ? 'bc' : 'tb', words);
  } else {
    const version: Uint8Array = new Uint8Array([
      network === 'mainnet' ? 0x00 : 0x6f,
    ]);
    const checksum: Uint8Array = (
      await hash256(new Uint8Array([...version, ...pubkeyHash]))
    ).slice(0, 4);

    return bs58.encode(
      new Uint8Array([...version, ...pubkeyHash, ...checksum]),
    );
  }
};

export const generateScriptAddress = async (
  script: string,
  type: 'legacy' | 'segwit' = 'segwit',
  network: 'mainnet' | 'testnet' = 'mainnet',
): Promise<string> => {
  await Validator.validateRedeemScript(script);

  const scriptHash: Uint8Array =
    type === 'segwit'
      ? await sha256(hexToBytes(script))
      : await hash160(hexToBytes(script));
  if (type === 'segwit') {
    const words: number[] = bech32.toWords(scriptHash);
    words.unshift(0); // segwit version
    return bech32.encode(network === 'mainnet' ? 'bc' : 'tb', words);
  } else {
    const version: Uint8Array = new Uint8Array([
      network === 'mainnet' ? 0x05 : 0xc4,
    ]);
    const checksum: Uint8Array = (
      await hash256(new Uint8Array([...version, ...scriptHash]))
    ).slice(0, 4);

    return bs58.encode(
      new Uint8Array([...version, ...scriptHash, ...checksum]),
    );
  }
};
