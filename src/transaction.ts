import { secp256k1 } from '@noble/curves/secp256k1';
import { hexToBytes, bytesToHex } from '@noble/hashes/utils';
import { Opcode } from './opcode.js';
import { hash256, sha256, sign } from './crypto.js';
import { padZeroHexN, reverseHex } from './encode.js';
import { getVarInt, pushData } from './data.js';
import {
  generateHashLockScript,
  generateMultiSigScript,
  generateSingleSigScript,
  getScriptByAddress,
} from './script.js';
import { getTapSigHash } from './tapscript.js';

export interface UTXO {
  id: string;
  index: number;
  value: number; // required in segWit
  script?: string; // required in taproot
}

export interface Target {
  address?: string;
  script?: string;
  value: number;
}

export class Transaction {
  private _version: string;
  private _locktime: string;
  private _inputs: UTXO[];
  private _outputs: Target[];
  private _inputScriptArr: string[];
  private _outputScriptArr: string[];
  private _inputAmountArr: string[];
  private _unsignedTx: string;
  private _sequence: string;
  private _segWitMarker = '00';
  private _segWitFlag = '01';
  private _witness: Map<number, string>;
  private _witnessMsgPrefix: Uint8Array;
  private _witnessMsgSuffix: Uint8Array;
  private _taprootMsgPrefix: Uint8Array;

  constructor() {
    this._inputs = [];
    this._outputs = [];
    this._version = '01000000';
    this._locktime = '00000000';
    this._inputScriptArr = [];
    this._outputScriptArr = [];
    this._inputAmountArr = [];
    this._unsignedTx = '';
    this._sequence = 'fdffffff'; // enable locktime and rbf as default
    this._witness = new Map<number, string>();
    this._witnessMsgPrefix = new Uint8Array(); // before outpoint
    this._witnessMsgSuffix = new Uint8Array(); // after sequence
    this._taprootMsgPrefix = new Uint8Array(); // before
  }

  public addInput = async (utxo: UTXO): Promise<void> => {
    await this._isSignedCheck('add input');
    this._inputs.push(utxo);
  };

  public addOutput = async (target: Target): Promise<void> => {
    await this._isSignedCheck('add output');
    if (!target.address && !target.script)
      throw new Error('Either address or script must be given for output');
    if (target.script && target.script.length > 20000)
      throw new Error('Output script must be less than 10k bytes');
    this._outputs.push(target);
  };

  public signAll = async (
    pubkey: string,
    privkey: string,
    type: 'legacy' | 'segwit' | 'taproot' = 'segwit',
    timeLockScript = '',
    secretHex = '',
  ): Promise<void> => {
    if (pubkey.length !== 66)
      throw new Error('pubkey must be compressed 33 bytes');
    if (privkey.length !== 64) throw new Error('privkey must be 32 bytes');

    for (let i = 0; i < this._inputs.length; i++) {
      await this.signInput(pubkey, privkey, i, type, timeLockScript, secretHex);
    }
  };

  public signInput = async (
    pubkey: string,
    privkey: string,
    index: number,
    type: 'legacy' | 'segwit' | 'taproot' = 'segwit',
    timeLockScript = '',
    secretHex = '',
  ): Promise<void> => {
    if (type !== 'taproot' && pubkey.length !== 66)
      throw new Error('pubkey must be compressed 33 bytes');
    if (type === 'taproot' && pubkey.length !== 0)
      throw new Error('schnorr pubkey is not required for taproot');

    if (privkey.length !== 64) throw new Error('privkey must be 32 bytes');

    const unsignedTx = await this._finalize();
    await this._sign(
      [pubkey],
      [privkey],
      unsignedTx,
      index,
      false,
      timeLockScript,
      secretHex,
      type,
    );
  };

  public multiSignInput = async (
    pubkey: string[],
    privkey: string[],
    index: number,
    type: 'legacy' | 'segwit' | 'taproot' = 'segwit',
    timeLockScript = '',
    secretHex = '',
  ): Promise<void> => {
    const unsignedTx = await this._finalize();
    await this._sign(
      pubkey,
      privkey,
      unsignedTx,
      index,
      true,
      timeLockScript,
      secretHex,
      type,
    );
  };

  public unlockHashInput = async (
    secretHex: string,
    index: number,
    type: 'legacy' | 'segwit' = 'segwit',
    timeLockScript = '',
  ): Promise<void> => {
    if (index > this._inputs.length - 1)
      throw new Error(
        `Out of range, tx contains only ${this._inputs.length} inputs`,
      );
    await this._finalize();
    // if not even, pad 0 at last
    secretHex.length % 2 !== 0 ? (secretHex += '0') : '';
    // script sig including secret and hash lock script
    const redeemScript =
      timeLockScript + (await generateHashLockScript(secretHex));
    const isSegWit = type === 'segwit' ? true : false;
    const scriptSig: string =
      '01' +
      Opcode.OP_1 + // as op_equalverify is used, trick to avoid clean stack err
      (isSegWit
        ? await getVarInt(secretHex.length / 2)
        : await pushData(secretHex)) +
      secretHex +
      (isSegWit
        ? await getVarInt(redeemScript.length / 2)
        : await pushData(redeemScript)) +
      redeemScript;
    isSegWit
      ? await this._setWitnessScriptSig(
          index,
          scriptSig,
          await this._getWitnessItemCount(
            ['count_for_OP_1'],
            [],
            false,
            timeLockScript,
            secretHex,
          ),
        )
      : await this._setInputScriptSig(index, scriptSig);
  };

  public getSignedHex = async (): Promise<string> => {
    const isSegWit: boolean = await this.isSegWit();
    // signed tx except witness and locktime
    // add witness field if exists
    let witness: string = '';
    for (let i = 0; i < this._inputScriptArr.length - 1; i++) {
      // push witness if exists('00' if not)
      witness += this._witness.has(i) ? this._witness.get(i) : '00';
    }
    return (
      this._version +
      (isSegWit ? this._segWitMarker + this._segWitFlag : '') +
      this._inputScriptArr.join('') +
      this._outputScriptArr.join('') +
      (witness.length === this._inputs.length * 2 ? '' : witness) +
      this._locktime
    );
  };

  // below are for custom smart contract
  public getInputHashToSign = async (
    redeemScript: string,
    index: number,
    type: 'legacy' | 'segwit' | 'taproot' = 'segwit',
  ): Promise<Uint8Array> => {
    const unsignedTx = await this._finalize();
    const sigHashType: string = '01000000';

    // op_pushdata and length in hex
    const scriptCodeLength: string =
      type === 'segwit'
        ? await getVarInt(redeemScript.length / 2)
        : await pushData(redeemScript);
    // add script length except op_pushdata(will add after sign)
    const scriptCode: string =
      scriptCodeLength.length === 2 || type === 'segwit'
        ? scriptCodeLength + redeemScript
        : scriptCodeLength.slice(2) + redeemScript;

    return await this._getHashToSign(
      unsignedTx,
      sigHashType,
      index,
      scriptCode,
      type,
    );
  };

  public signInputByScriptSig = async (
    sigList: string[],
    redeemScript: string,
    index: number,
    type: 'legacy' | 'segwit' = 'segwit',
  ): Promise<void> => {
    if (type === 'segwit') {
      // witness stack item count (including redeem script)
      const witnessCount = await getVarInt(sigList.length + 1);
      let scriptSig = '';
      // encode bytes to read each witness item
      for (let i = 0; i < sigList.length; i++) {
        scriptSig += (await getVarInt(sigList[i].length / 2)) + sigList[i];
      }
      // encode bytes to read redeem script
      scriptSig += (await getVarInt(redeemScript.length / 2)) + redeemScript;
      await this._setWitnessScriptSig(index, scriptSig, witnessCount);
    } else {
      let scriptSig = '';
      // encode bytes to read each sig item
      for (let i = 0; i < sigList.length; i++) {
        scriptSig += (await pushData(sigList[i])) + sigList[i];
      }
      // encode bytes to read redeem script
      scriptSig += (await pushData(redeemScript)) + redeemScript;
      await this._setInputScriptSig(index, scriptSig);
    }
  };

  public getId = async (): Promise<string> => {
    // little endian of double sha256 serialized tx
    return bytesToHex(
      (await hash256(hexToBytes(await this.getSignedHex()))).reverse(),
    );
  };

  // must be set >= any of timelock input block height
  public setLocktime = async (block: number): Promise<void> => {
    await this._isSignedCheck('set locktime');
    this._locktime = await reverseHex(await padZeroHexN(block.toString(16), 8));
  };

  public disableRBF = async (): Promise<void> => {
    await this._isSignedCheck('disable rbf');
    this._sequence = 'feffffff';
  };

  public disableLocktime = async (): Promise<void> => {
    await this._isSignedCheck('disable locktime');
    this._sequence = 'ffffffff';
  };

  public isSegWit = async (): Promise<boolean> => {
    return this._witness.size !== 0 ? true : false;
  };

  private _finalize = async (): Promise<string> => {
    // if already finalized, just return
    if (this._unsignedTx.length !== 0) return this._unsignedTx;

    const inputScript: string[] = await this._finalizeInputs();
    const outputScript: string[] = await this._finalizeOutputs();
    await this._finalizeSegwit();

    this._unsignedTx =
      this._version +
      inputScript.join('') +
      outputScript.join('') +
      this._locktime;

    return this._unsignedTx;
  };

  private _finalizeInputs = async (): Promise<string[]> => {
    // if already finalized, just return
    if (this._inputScriptArr.length !== 0) return this._inputScriptArr;
    // input count in varInt
    const inputCount: string = await getVarInt(this._inputs.length);
    this._inputScriptArr.push(inputCount);
    // get input script hex
    for (const input of this._inputs) {
      /* 
      tx id + tx index + empty script sig + sequence
      */
      const inputScript: string =
        (await reverseHex(input.id)) +
        (await reverseHex(await padZeroHexN(input.index.toString(16), 8))) +
        Opcode.OP_0 + // will be replaced into scriptPubKey to sign
        this._sequence;
      // for segwit, little endian input amount list
      const inputAmount: string = await reverseHex(
        await padZeroHexN(
          Math.floor((input.value as number) * 10 ** 8).toString(16),
          16,
        ),
      );

      this._inputScriptArr.push(inputScript);
      this._inputAmountArr.push(inputAmount);
    }

    return this._inputScriptArr;
  };

  private _finalizeOutputs = async (): Promise<string[]> => {
    // if already finalized, just return
    if (this._outputScriptArr.length !== 0) return this._outputScriptArr;
    // output count in varInt
    const outputCount: string = await getVarInt(this._outputs.length);
    this._outputScriptArr.push(outputCount);
    // get output script hex
    for (const output of this._outputs) {
      const value: string = await reverseHex(
        await padZeroHexN(Math.floor(output.value * 10 ** 8).toString(16), 16),
      );
      const scriptPubKey: string = output.address
        ? await getScriptByAddress(output.address as string)
        : (output.script as string);
      // value + scriptPubKey
      this._outputScriptArr.push(
        value + (await getVarInt(scriptPubKey.length / 2)) + scriptPubKey,
      );
    }

    return this._outputScriptArr;
  };

  private _finalizeSegwit = async (): Promise<void> => {
    const versionByte: Uint8Array = hexToBytes(this._version);
    const prevHash: Uint8Array = await sha256(
      hexToBytes(
        this._inputScriptArr
          .reduce(
            (accumulator, currentValue) =>
              accumulator + currentValue.slice(0, 72),
            '',
          )
          .slice(2),
      ),
    );
    const sequenceHash: Uint8Array = await sha256(
      hexToBytes(this._sequence.repeat(this._inputs.length)),
    );
    this._witnessMsgPrefix = new Uint8Array([
      ...versionByte,
      ...(await sha256(prevHash)),
      ...(await sha256(sequenceHash)),
    ]);
    const outputHash: Uint8Array = await sha256(
      hexToBytes(this._outputScriptArr.join('').slice(2)),
    );
    // below are little endians
    const lockTimeByte: Uint8Array = hexToBytes(this._locktime);
    this._witnessMsgSuffix = new Uint8Array([
      ...(await sha256(outputHash)),
      ...lockTimeByte,
    ]);

    // taproot
    await this._finalizeTaproot(
      versionByte,
      lockTimeByte,
      prevHash,
      sequenceHash,
      outputHash,
    );
  };

  private _finalizeTaproot = async (
    versionByte: Uint8Array,
    lockTimeByte: Uint8Array,
    prevHash: Uint8Array,
    sequenceHash: Uint8Array,
    outputHash: Uint8Array,
  ): Promise<void> => {
    const valueHash: Uint8Array = await sha256(
      hexToBytes(this._inputAmountArr.join('')),
    );

    let scriptPubKeyJoined = '';

    for (const input of this._inputs) {
      scriptPubKeyJoined +=
        (await getVarInt((input.script?.length as number) / 2)) + input.script;
    }
    const scriptPubKeyHash: Uint8Array = await sha256(
      hexToBytes(scriptPubKeyJoined),
    );

    this._taprootMsgPrefix = new Uint8Array([
      ...versionByte,
      ...lockTimeByte,
      ...prevHash,
      ...valueHash,
      ...scriptPubKeyHash,
      ...sequenceHash,
      ...outputHash,
    ]);
  };

  private _sign = async (
    pubkey: string[],
    privkey: string[],
    unsignedTx: string,
    inputIdx: number,
    isMultiSig: boolean,
    timeLockScript = '',
    secretHex = '',
    type: 'legacy' | 'segwit' | 'taproot' = 'segwit',
  ): Promise<void> => {
    // get script pub key to sign
    let scriptCode: string = '';
    // if taproot, no need for script code
    if (type !== 'taproot') {
      // hash lock redeem script if unlock hash exists
      let hashLockScript: string = '';
      if (secretHex.length !== 0) {
        hashLockScript = await generateHashLockScript(secretHex);
        // if secretHex not even, pad 0 at last
        secretHex.length % 2 !== 0 ? (secretHex += '0') : '';
        // add bytes to read secretHex
        secretHex =
          (type !== 'legacy'
            ? await getVarInt(secretHex.length / 2)
            : await pushData(secretHex)) + secretHex;
      }
      if (!isMultiSig) {
        // default script sig type is p2pkh
        const p2pkh = await generateSingleSigScript(pubkey[0]);
        scriptCode = timeLockScript + hashLockScript + p2pkh;
      } else {
        // multi sig type of p2sh script
        const p2sh: string = await generateMultiSigScript(
          privkey.length,
          pubkey,
        );
        scriptCode = timeLockScript + hashLockScript + p2sh;
      }
    }
    // op_pushdata and length in hex
    const scriptCodeLength =
      type !== 'legacy'
        ? await getVarInt(scriptCode.length / 2)
        : await pushData(scriptCode);
    // add script length except op_pushdata(will add after sign)
    if (type !== 'taproot') {
      scriptCode =
        scriptCodeLength.length === 2 || type !== 'legacy'
          ? scriptCodeLength + scriptCode
          : scriptCodeLength.slice(2) + scriptCode;
    }
    // get msg hash to sign and generate DER signature
    const sigHashType: string = '01000000';
    const msgHash: Uint8Array = await this._getHashToSign(
      unsignedTx,
      sigHashType,
      inputIdx,
      scriptCode,
      type,
    );

    // get script sig to insert
    let scriptSig: string = '';
    if (!isMultiSig) {
      // p2pkh scrip sig
      const signature: string = await sign(
        msgHash,
        privkey[0],
        sigHashType,
        type !== 'taproot' ? 'secp256k1' : 'schnorr',
      );
      scriptSig +=
        (signature.length / 2).toString(16) +
        signature +
        (type !== 'taproot'
          ? (await pushData(pubkey[0])) + pubkey[0] + secretHex
          : '');

      // scriptPubKey(redeem script) is in script sig if p2sh
      if (timeLockScript.length !== 0 || secretHex.length !== 0)
        scriptSig +=
          (scriptCodeLength.length !== 2 && type === 'legacy'
            ? scriptCodeLength.slice(0, 2)
            : '') + scriptCode; // pushdata
    } else {
      // p2sh script sig
      // multi sig for p2sh script
      let multiSig: string = Opcode.OP_0; //one extra unused value removed from the stack for OP_CHECKMULTISIG
      for (let i = 0; i < privkey.length; i++) {
        if (privkey[i].length !== 64)
          throw new Error('privkey must be 32 bytes');
        const signature =
          secp256k1.sign(msgHash, privkey[i]).toDERHex() +
          sigHashType.slice(0, 2);
        multiSig += (signature.length / 2).toString(16) + signature;
      }
      // scriptPubKey(redeem script) is in script sig as p2sh
      scriptSig +=
        multiSig +
        secretHex +
        (scriptCodeLength.length !== 2 && type === 'legacy'
          ? scriptCodeLength.slice(0, 2)
          : '') + // pushdata
        scriptCode;
    }

    type !== 'legacy'
      ? await this._setWitnessScriptSig(
          inputIdx,
          scriptSig,
          type === 'taproot'
            ? '01'
            : await this._getWitnessItemCount(
                pubkey,
                privkey,
                isMultiSig,
                timeLockScript,
                secretHex,
              ),
        )
      : await this._setInputScriptSig(inputIdx, scriptSig);
  };

  private _getHashToSign = async (
    unsignedTx: string,
    sigHashType: string,
    inputIdx: number,
    scriptCode: string,
    type: 'legacy' | 'segwit' | 'taproot' = 'segwit',
  ): Promise<Uint8Array> => {
    // index to insert script sig
    if (inputIdx > this._inputs.length - 1)
      throw new Error(
        `Out of range, tx contains only ${this._inputs.length} inputs`,
      );
    if (type === 'taproot') {
      const epoch: number = 0;
      const spendType: number = 0; // no annex
      // little endian
      const inputIdxBytes: Uint8Array = await hexToBytes(
        await padZeroHexN(inputIdx.toString(16), 8),
      ).reverse();
      return await getTapSigHash(
        new Uint8Array([
          epoch,
          parseInt(sigHashType.slice(0, 2)),
          ...this._taprootMsgPrefix,
          spendType,
          ...inputIdxBytes,
        ]),
      );
    } else if (type === 'segwit') {
      // below are little endians
      const outpointByte: Uint8Array = hexToBytes(
        this._inputScriptArr[inputIdx + 1].slice(0, 72),
      );
      const scriptCodeByte: Uint8Array = hexToBytes(scriptCode);
      const valueByte: Uint8Array = hexToBytes(
        await padZeroHexN(
          Math.floor(
            (this._inputs[inputIdx].value as number) * 10 ** 8,
          ).toString(16),
          16,
        ),
      ).reverse();
      const sequenceByte: Uint8Array = hexToBytes(this._sequence);
      const sigHashByte: Uint8Array = hexToBytes(sigHashType);
      return await hash256(
        new Uint8Array([
          ...this._witnessMsgPrefix,
          ...outpointByte,
          ...scriptCodeByte,
          ...valueByte,
          ...sequenceByte,
          ...this._witnessMsgSuffix,
          ...sigHashByte,
        ]),
      );
    } else {
      const txToSign: string = unsignedTx + sigHashType;
      const index: number = await this._getScriptCodeIdx(inputIdx);
      return await hash256(
        hexToBytes(
          txToSign.slice(0, index) + scriptCode + txToSign.slice(index + 2),
        ),
      );
    }
  };

  private _getScriptCodeIdx = async (index: number): Promise<number> => {
    return (
      8 + // tx version
      this._inputScriptArr[0].length + // tx input count(varInt)
      (64 + 8 + 2 + 8) * index + // txid + tx index + empty script sig + sequence
      (64 + 8) // (txid + tx index) of first input
    );
  };

  private _setInputScriptSig = async (
    index: number,
    scriptSig: string,
  ): Promise<void> => {
    if (scriptSig.length > 3300)
      throw new Error('script sig must be less than 1650 bytes');

    const inputScript: string = this._inputScriptArr[index + 1];
    const finalInputScript: string =
      inputScript.slice(0, inputScript.length - 10) +
      (await getVarInt(scriptSig.length / 2)) +
      scriptSig +
      inputScript.slice(inputScript.length - 8);
    // replace unsigned input into signed
    this._inputScriptArr.splice(index + 1, 1, finalInputScript);
  };

  private _setWitnessScriptSig = async (
    index: number,
    witnessScriptSig: string,
    itemCount: string,
  ): Promise<void> => {
    if (witnessScriptSig.length > 20000)
      throw new Error('witness script must be less than 10,000 bytes');
    this._witness.set(index, itemCount + witnessScriptSig);
  };

  private _getWitnessItemCount = async (
    pubkey: string[],
    privkey: string[],
    isMultiSig: boolean,
    timeLockScript = '',
    secretHex = '',
  ): Promise<string> => {
    let witnessCount: number = privkey.length; // signature count
    secretHex.length !== 0 ? (witnessCount += 1) : ''; // hash count
    isMultiSig
      ? (witnessCount += 2) // include OP_0 and redeem script
      : timeLockScript.length !== 0
      ? (witnessCount += 1) // include redeem script only
      : secretHex.length !== 0
      ? (witnessCount += 1) // include redeem script only
      : '';
    !isMultiSig ? (witnessCount += pubkey.length) : ''; // pubkey count
    return padZeroHexN(witnessCount.toString(16), 2);
  };

  private _isSignedCheck = async (taskMsg: string): Promise<void> => {
    // if already finalized, at least one input is signed
    if (this._outputScriptArr.length !== 0)
      throw new Error(`Cannot ${taskMsg} after any of input is signed`);
  };
}
