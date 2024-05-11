import { hexToBytes } from '@noble/hashes/utils';
import bs58 from 'bs58';
import { hash160, hash256, sha256 } from './crypto.js';
import { bech32, bech32m } from 'bech32';
import { Validator } from './validator.js';
export const generateAddress = async (pubkey, type = 'segwit', network = 'mainnet') => {
    await Validator.validateKeyPair(pubkey, '', type === 'taproot' ? 'schnorr' : 'ecdsa');
    if (type === 'taproot') {
        const words = bech32m.toWords(hexToBytes(pubkey));
        words.unshift(1); // taproot is segwit version 1
        return bech32m.encode(network === 'mainnet' ? 'bc' : 'tb', words);
    }
    const pubkeyHash = await hash160(hexToBytes(pubkey));
    if (type === 'segwit') {
        const words = bech32.toWords(pubkeyHash);
        words.unshift(0); // segwit version
        return bech32.encode(network === 'mainnet' ? 'bc' : 'tb', words);
    }
    else {
        const version = new Uint8Array([
            network === 'mainnet' ? 0x00 : 0x6f,
        ]);
        const checksum = (await hash256(new Uint8Array([...version, ...pubkeyHash]))).slice(0, 4);
        return bs58.encode(new Uint8Array([...version, ...pubkeyHash, ...checksum]));
    }
};
export const generateScriptAddress = async (script, type = 'segwit', network = 'mainnet') => {
    await Validator.validateRedeemScript(script);
    const scriptHash = type === 'segwit'
        ? await sha256(hexToBytes(script))
        : await hash160(hexToBytes(script));
    if (type === 'segwit') {
        const words = bech32.toWords(scriptHash);
        words.unshift(0); // segwit version
        return bech32.encode(network === 'mainnet' ? 'bc' : 'tb', words);
    }
    else {
        const version = new Uint8Array([
            network === 'mainnet' ? 0x05 : 0xc4,
        ]);
        const checksum = (await hash256(new Uint8Array([...version, ...scriptHash]))).slice(0, 4);
        return bs58.encode(new Uint8Array([...version, ...scriptHash, ...checksum]));
    }
};
