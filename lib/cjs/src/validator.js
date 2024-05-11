"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Validator = void 0;
// hex is not strictly checked as will be checked when finalize, for performance
class Validator {
    // validate script
    static validateRedeemScript = async (redeemScript) => {
        // check redeem script size
        if (redeemScript.length > 1040)
            throw new Error('Redeem script must be equal or less than 520 bytes');
    };
    // validate script
    static validateScriptSig = async (scriptSig) => {
        // check script sig size
        if (scriptSig.length > 3300)
            throw new Error('Script sig must be less than 1650 bytes');
    };
    // validate script
    static validateWitnessItem = async (item) => {
        // check witness item
        if (item.length > 1040)
            throw new Error('Each witness stack item must be equal or less than 520 bytes if not taproot');
    };
    // validate script
    static validateWitnessScript = async (witnessScript) => {
        // check witness script size
        if (witnessScript.length > 7200)
            throw new Error('Witness script must be equal or less than 3,600 bytes if not taproot');
    };
    // validate block lock height
    static validateBlockLock = async (block) => {
        if (block >= 500000000)
            throw new Error('Block height must be < 500,000,000');
    };
    // validate keypair for each type
    static validateKeyPair = async (pubkey, privkey, type = 'ecdsa') => {
        if (pubkey) {
            if (type === 'schnorr') {
                if (pubkey?.length !== 64)
                    throw new Error('Schnorr pubkey must be 32 bytes');
            }
            else if (pubkey?.length !== 66) {
                throw new Error('Pubkey must be compressed 33 bytes');
            }
        }
        if (privkey && privkey?.length !== 64)
            throw new Error('Privkey must be 32 bytes');
    };
    // validate keypair for each type
    static validateKeyPairBatch = async (pubkey, privkey, type) => {
        const promiseArr = [];
        for (let i = 0; i < pubkey.length; i++)
            promiseArr.push(this.validateKeyPair(pubkey[i], privkey[i], type));
        await Promise.all(promiseArr);
    };
    // validate minimal push
    static validateMinimalPush = async (data) => {
        // check minimal push
        if (data.length !== 0 && Number('0x' + data) <= 16)
            throw new Error('Pushing a 1-byte sequence of byte 0x01 through 0x10 must use OP_n');
        if (data === '81')
            throw new Error('Pushing the byte 0x81 must use OP_1NEGATE');
    };
    // validate uint64
    static validateUint64 = async (num) => {
        if (num < 0 || !Number.isInteger(num))
            throw new Error('Number must be uint64');
    };
}
exports.Validator = Validator;
