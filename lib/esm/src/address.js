import { hexToBytes } from '@noble/hashes/utils';
import bs58 from 'bs58';
import { hash160, hash256 } from './crypto.js';
export const generateAddress = async (pubkey, network = 'mainnet') => {
    if (pubkey.length !== 66)
        throw new Error('pubkey must be compressed 33 bytes');
    const pubkeyHash = await hash160(hexToBytes(pubkey));
    const version = new Uint8Array([
        network === 'mainnet' ? 0x1e : 0x71,
    ]);
    const checksum = (await hash256(new Uint8Array([...version, ...pubkeyHash]))).slice(0, 4);
    const bs58encoded = bs58.encode(new Uint8Array([...version, ...pubkeyHash, ...checksum]));
    return bs58encoded;
};
export const generateScriptAddress = async (script, network = 'mainnet') => {
    if (script.length > 1040)
        throw new Error('Redeem script must be less than 520 bytes');
    const scriptHash = await hash160(hexToBytes(script));
    const version = new Uint8Array([
        network === 'mainnet' ? 0x16 : 0xc4,
    ]);
    const checksum = (await hash256(new Uint8Array([...version, ...scriptHash]))).slice(0, 4);
    const bs58encoded = bs58.encode(new Uint8Array([...version, ...scriptHash, ...checksum]));
    return bs58encoded;
};
