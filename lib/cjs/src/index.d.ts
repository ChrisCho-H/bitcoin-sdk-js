export interface UTXO {
    id: string;
    index: number;
}
export interface Target {
    address?: string;
    script?: string;
    amount: number;
}
export interface KeyPair {
    publicKey: string;
    privateKey: string;
}
export declare const generateAddress: (pubkey: string, network?: string) => Promise<string>;
export declare const generateSingleSigScript: (pubkey: string) => Promise<string>;
export declare const generateMultiSigScript: (privkeyCount: number, pubkeys: string[]) => Promise<string>;
export declare const generateScriptAddress: (script: string, network?: string) => Promise<string>;
export declare const generateKeyPair: () => Promise<KeyPair>;
export declare const generateDataScript: (dataToWrite: string, encode?: 'utf-8' | 'hex') => Promise<string>;
export declare const generateTimeLockScript: (block?: number, utc?: number, isAbsolute?: boolean) => Promise<string>;
export declare const generateHashLockScript: (secretHex: string) => Promise<string>;
export declare const getScriptByAddress: (address: string, withLength?: boolean) => Promise<string>;
export declare class Transaction {
    private _version;
    private _locktime;
    private _inputs;
    private _outputs;
    private _inputScriptArr;
    private _outputScriptArr;
    private _unsignedTx;
    private _sequence;
    constructor();
    addInput: (utxo: UTXO) => Promise<void>;
    addOutput: (target: Target) => Promise<void>;
    signAll: (pubkey: string, privkey: string) => Promise<void>;
    signInput: (pubkey: string, privkey: string, index: number, timeLockScript?: string, secretHex?: string) => Promise<void>;
    multiSignInput: (pubkey: string[], privkey: string[], index: number, timeLockScript?: string, secretHex?: string) => Promise<void>;
    unlockHashInput: (secretHex: string, index: number, timeLockScript?: string) => Promise<void>;
    getSignedHex: () => Promise<string>;
    getId: () => Promise<string>;
    setLocktime: (block: number) => Promise<void>;
    disableRBF: () => Promise<void>;
    disableLocktime: () => Promise<void>;
    private _finalize;
    private _finalizeInputs;
    private _finalizeOutputs;
    private _sign;
    private _getScriptCodeIdx;
    private _setInputScriptSig;
    private _isSignedCheck;
}
