export declare const generateAddress: (pubkey: string, isSegwit?: boolean, network?: 'mainnet' | 'testnet') => Promise<string>;
export declare const generateScriptAddress: (script: string, isSegwit?: boolean, network?: 'mainnet' | 'testnet') => Promise<string>;
