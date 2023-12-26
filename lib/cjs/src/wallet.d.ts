export interface KeyPair {
    publicKey: string;
    privateKey: string;
}
export declare const generateKeyPair: () => Promise<KeyPair>;
