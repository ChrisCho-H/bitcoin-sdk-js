export declare class Validator {
    static validateRedeemScript: (redeemScript: string) => Promise<void>;
    static validateScriptSig: (scriptSig: string) => Promise<void>;
    static validateWitnessItem: (item: string) => Promise<void>;
    static validateWitnessScript: (witnessScript: string) => Promise<void>;
    static validateBlockLock: (block: number) => Promise<void>;
    static validateKeyPair: (pubkey?: string, privkey?: string, type?: 'ecdsa' | 'schnorr') => Promise<void>;
    static validateKeyPairBatch: (pubkey: string[], privkey: string[], type: 'ecdsa' | 'schnorr') => Promise<void>;
    static validateMinimalPush: (data: string) => Promise<void>;
    static validateUint64: (num: number) => Promise<void>;
}
