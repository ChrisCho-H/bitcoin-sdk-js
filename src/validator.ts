// hex is not strictly checked as will be checked when finalize, for performance
export class Validator {
  // validate script
  public static validateRedeemScript = async (
    redeemScript: string,
  ): Promise<void> => {
    // check redeem script size
    if (redeemScript.length > 1040)
      throw new Error('Redeem script must be equal or less than 520 bytes');
  };
  // validate script
  public static validateScriptSig = async (
    scriptSig: string,
  ): Promise<void> => {
    // check script sig size
    if (scriptSig.length > 3300)
      throw new Error('Script sig must be less than 1650 bytes');
  };
  // validate script
  public static validateWitnessItem = async (item: string): Promise<void> => {
    // check witness item
    if (item.length > 1040)
      throw new Error(
        'Each witness stack item must be equal or less than 520 bytes if not taproot',
      );
  };
  // validate script
  public static validateWitnessScript = async (
    witnessScript: string,
  ): Promise<void> => {
    // check witness script size
    if (witnessScript.length > 7200)
      throw new Error('Witness script must be equal or less than 3,600 bytes if not taproot');
  };
  // validate block lock height
  public static validateBlockLock = async (block: number): Promise<void> => {
    if (block >= 500000000)
      throw new Error('Block height must be < 500,000,000');
  };
  // validate keypair for each type
  public static validateKeyPair = async (
    pubkey?: string,
    privkey?: string,
    type: 'ecdsa' | 'schnorr' = 'ecdsa',
  ): Promise<void> => {
    if (pubkey) {
      if (type === 'schnorr') {
        if (pubkey?.length !== 64)
          throw new Error('Schnorr pubkey must be 32 bytes');
      } else if (pubkey?.length !== 66) {
        throw new Error('Pubkey must be compressed 33 bytes');
      }
    }
    if (privkey && privkey?.length !== 64)
      throw new Error('Privkey must be 32 bytes');
  };
  // validate keypair for each type
  public static validateKeyPairBatch = async (
    pubkey: string[],
    privkey: string[],
    type: 'ecdsa' | 'schnorr',
  ): Promise<void> => {
    const promiseArr: Promise<void>[] = [];
    for (let i: number = 0; i < pubkey.length; i++)
      promiseArr.push(this.validateKeyPair(pubkey[i], privkey[i], type));
    await Promise.all(promiseArr);
  };
  // validate minimal push
  public static validateMinimalPush = async (data: string): Promise<void> => {
    // check minimal push
    if (data.length !== 0 && Number('0x' + data) <= 16)
      throw new Error(
        'Pushing a 1-byte sequence of byte 0x01 through 0x10 must use OP_n',
      );
    if (data === '81')
      throw new Error('Pushing the byte 0x81 must use OP_1NEGATE');
  };
  // validate uint64
  public static validateUint64 = async (num: number): Promise<void> => {
    if (num < 0 || !Number.isInteger(num))
      throw new Error('Number must be uint64');
  };
}
