export declare const padZeroHexN: (hex: string, n: number) => Promise<string>;
export declare const reverseHex: (hex: string) => Promise<string>;
export declare const hexToBytes: (hex: string) => Promise<Uint8Array>;
export declare const bytesToHex: (bytes: Uint8Array) => Promise<string>;
export declare const utf8ToBytes: (str: string) => Promise<Uint8Array>;
export declare const bytesToBase64: (bytes: Uint8Array) => Promise<string>;
export declare const base64ToBytes: (str: string) => Promise<Uint8Array>;
export declare const scriptNum: (num: number) => Promise<string>;
