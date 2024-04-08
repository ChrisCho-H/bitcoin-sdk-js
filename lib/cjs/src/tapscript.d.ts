interface TapTweakedPubkey {
    parityBit: '02' | '03';
    tweakedPubKey: string;
}
export declare const getTapLeaf: (script: string, tapLeafVersion?: number) => Promise<Uint8Array>;
export declare const getTapBranch: (tapLeafPair: Uint8Array[]) => Promise<Uint8Array>;
export declare const getTapTweak: (schnorrPubkey: string, tapRoot: Uint8Array) => Promise<Uint8Array>;
export declare const getTapTag: (tapTagHex: string) => Promise<Uint8Array>;
export declare const getTapTweakedPubkey: (schnorrPubkey: string, tapTweak: Uint8Array) => Promise<TapTweakedPubkey>;
export declare const getTapTweakedPrivkey: (schnorrPrivkey: string, tapTweak: Uint8Array) => Promise<string>;
export declare const getTapSigHash: (sigMsg: Uint8Array) => Promise<Uint8Array>;
export declare const getTapControlBlock: (schnorrPubkey: string, tapLeaf: Uint8Array, tweakedPubKeyParityBit: '02' | '03', tapLeafVersion?: number) => Promise<string>;
export {};
