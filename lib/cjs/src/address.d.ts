export declare const generateAddress: (pubkey: string, type?: 'legacy' | 'segwit', network?: 'mainnet' | 'testnet') => Promise<string>;
export declare const generateScriptAddress: (script: string, type?: 'legacy' | 'segwit', network?: 'mainnet' | 'testnet') => Promise<string>;
