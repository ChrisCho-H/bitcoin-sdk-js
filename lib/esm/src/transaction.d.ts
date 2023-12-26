export interface UTXO {
    id: string;
    index: number;
    value: number;
}
export interface Target {
    address?: string;
    script?: string;
    value: number;
}
export declare class Transaction {
    private _version;
    private _locktime;
    private _inputs;
    private _outputs;
    private _inputScriptArr;
    private _outputScriptArr;
    private _unsignedTx;
    private _sequence;
    private _segWitMarker;
    private _segWitFlag;
    private _witness;
    private _witnessPrefix;
    private _witnessSuffix;
    constructor();
    addInput: (utxo: UTXO) => Promise<void>;
    addOutput: (target: Target) => Promise<void>;
    signAll: (pubkey: string, privkey: string, isSegWit?: boolean) => Promise<void>;
    signInput: (pubkey: string, privkey: string, index: number, timeLockScript?: string, secretHex?: string, isSegWit?: boolean) => Promise<void>;
    multiSignInput: (pubkey: string[], privkey: string[], index: number, timeLockScript?: string, secretHex?: string, isSegWit?: boolean) => Promise<void>;
    unlockHashInput: (secretHex: string, index: number, timeLockScript?: string, isSegWit?: boolean) => Promise<void>;
    getSignedHex: () => Promise<string>;
    getId: () => Promise<string>;
    setLocktime: (block: number) => Promise<void>;
    disableRBF: () => Promise<void>;
    disableLocktime: () => Promise<void>;
    isSegWit: () => Promise<boolean>;
    private _finalize;
    private _finalizeInputs;
    private _finalizeOutputs;
    private _finalizeSegwit;
    private _sign;
    private _getHashToSign;
    private _getScriptCodeIdx;
    private _setInputScriptSig;
    private _setWitnessScriptSig;
    private _getWitnessItemCount;
    private _isSignedCheck;
}
