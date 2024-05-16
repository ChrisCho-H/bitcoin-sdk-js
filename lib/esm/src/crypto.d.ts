export declare const hash160: (hex: Uint8Array) => Promise<Uint8Array>;
export declare const hash256: (hex: Uint8Array) => Promise<Uint8Array>;
export declare const ripemd160: (hex: Uint8Array) => Promise<Uint8Array>;
export declare const sha256: (hex: Uint8Array) => Promise<Uint8Array>;
export declare const sign: (msgHash: Uint8Array, privkey: string, type?: 'ecdsa' | 'schnorr', sigHashType?: string) => Promise<string>;
export declare const verify: (signature: string, msgHash: Uint8Array, pubkey: string, type?: 'ecdsa' | 'schnorr', sigHashType?: string) => Promise<boolean>;
export declare const signMessage: (msg: string, privkey: string, address: string) => Promise<string>;
export declare const verifyMessage: (msg: string, signature: string, address: string) => Promise<boolean>;
