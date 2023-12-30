import { hexToBytes } from '@noble/hashes/utils';
import bs58 from 'bs58';
import { hash160, hash256, sha256 } from './crypto.js';
import { bech32 } from 'bech32';
export const generateAddress = async (pubkey, isSegwit = true, network = 'mainnet') => {
    if (pubkey.length !== 66)
        throw new Error('pubkey must be compressed 33 bytes');
    const pubkeyHash = await hash160(hexToBytes(pubkey));
    if (isSegwit) {
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
export const generateScriptAddress = async (script, isSegwit = true, network = 'mainnet') => {
    if (script.length > 1040)
        throw new Error('Redeem script must be less than 520 bytes');
    const scriptHash = isSegwit
        ? await sha256(hexToBytes(script))
        : await hash160(hexToBytes(script));
    if (isSegwit) {
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