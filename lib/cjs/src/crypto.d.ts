export declare const hash160: (hex: Uint8Array) => Promise<Uint8Array>;
export declare const hash256: (hex: Uint8Array) => Promise<Uint8Array>;
export declare const ripemd160: (hex: Uint8Array) => Promise<Uint8Array>;
export declare const sha256: (hex: Uint8Array) => Promise<Uint8Array>;
export declare const sign: (msgHash: Uint8Array, privkey: string, type?: 'secp256k1' | 'schnorr', sigHashType?: string) => Promise<string>;
