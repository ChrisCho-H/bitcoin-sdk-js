export interface UTXO {
    id: string;
    index: number;
    value: number;
    script?: string;
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
    private _inputAmountArr;
    private _unsignedTx;
    private _sequence;
    private _segWitMarker;
    private _segWitFlag;
    private _witness;
    private _witnessMsgPrefix;
    private _witnessMsgSuffix;
    private _taprootMsgPrefix;
    constructor();
    addInput: (utxo: UTXO) => Promise<void>;
    addOutput: (target: Target) => Promise<void>;
    signAll: (pubkey: string, privkey: string, type?: 'legacy' | 'segwit' | 'taproot', timeLockScript?: string, secretHex?: string, sigHashType?: string) => Promise<void>;
    signInput: (pubkey: string, privkey: string, index: number, type?: 'legacy' | 'segwit' | 'taproot', timeLockScript?: string, secretHex?: string, sigHashType?: string) => Promise<void>;
    multiSignInput: (pubkey: string[], privkey: string[], index: number, type?: 'legacy' | 'segwit' | 'taproot', timeLockScript?: string, secretHex?: string, sigHashType?: string) => Promise<void>;
    unlockHashInput: (secretHex: string, index: number, type?: 'legacy' | 'segwit', timeLockScript?: string) => Promise<void>;
    getSignedHex: () => Promise<string>;
    getInputHashToSign: (redeemScript: string, index: number, type?: 'legacy' | 'segwit' | 'tapscript', sigHashType?: string, keyVersion?: string) => Promise<Uint8Array>;
    signInputByScriptSig: (sigStack: string[], index: number, type?: 'legacy' | 'segwit') => Promise<void>;
    getId: () => Promise<string>;
    setLocktime: (block: number) => Promise<void>;
    disableRBF: () => Promise<void>;
    disableLocktime: () => Promise<void>;
    isSegWit: () => Promise<boolean>;
    private _finalize;
    private _finalizeInputs;
    private _finalizeOutputs;
    private _finalizeSegwit;
    private _finalizeTaproot;
    private _sign;
    private _getHashToSign;
    private _getScriptCodeIdx;
    private _setInputScriptSig;
    private _setWitnessScriptSig;
    private _getWitnessItemCount;
    private _isSignedCheck;
}
