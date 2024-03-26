export declare const getScriptByAddress: (address: string) => Promise<string>;
export declare const generateScriptHash: (script: string, type?: 'legacy' | 'segwit') => Promise<string>;
export declare const generateSingleSigScript: (pubkey: string, type?: 'legacy' | 'segwit' | 'taproot') => Promise<string>;
export declare const generateMultiSigScript: (privkeyCount: number, pubkeys: string[]) => Promise<string>;
export declare const generateTimeLockScript: (block: number) => Promise<string>;
export declare const generateHashLockScript: (secretHex: string) => Promise<string>;
export declare const generateDataScript: (dataToWrite: string, encode?: 'utf-8' | 'hex') => Promise<string>;
