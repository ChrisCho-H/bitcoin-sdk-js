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
import { getTapLeaf, getTapSigHash } from './tapscript.js';
import { Validator } from './validator.js';
import { getPublicKey } from './wallet.js';

export interface UTXO {
  txHash: string;
  index: number;
  value: number; // required in segwit
  script?: string; // required in taproot
  sequence?: string; // default to 'fdffffff'
}

export interface Target {
  address?: string;
  script?: string;
  value: number;
}

// for internal use
interface InputScript {
  txHash: string;
  index: string;
  scriptSig: string;
  sequence: string;
  amount: string;
}
interface OutputScript {
  value: string;
  scriptPubKey: string;
}

export class Transaction {
  private _inputs: UTXO[];
  private _outputs: Target[];
  private _inputScript: Map<number, InputScript>;
  private _outputScript: Map<number, OutputScript>;
  private _witness: Map<number, string>;
  private _version = '01000000';
  private _locktime = '00000000';
  private _defaultSequence = 'fdffffff'; // enable locktime and rbf as default
  private _unsignedTx = '';
  private _segWitMarker = '00';
  private _segWitFlag = '01';
  private _witnessMsgPrefix: Uint8Array;
  private _witnessMsgSuffix: Uint8Array;
  private _taprootMsgPrefix: Uint8Array;

  constructor() {
    this._inputs = [];
    this._outputs = [];
    this._witness = new Map<number, string>();
    this._inputScript = new Map<number, InputScript>();
    this._outputScript = new Map<number, OutputScript>();
    this._witnessMsgPrefix = new Uint8Array(); // before outpoint
    this._witnessMsgSuffix = new Uint8Array(); // after sequence
    this._taprootMsgPrefix = new Uint8Array(); // before
  }

  public addInput = async (utxo: UTXO): Promise<void> => {
    await this._isSignedCheck('add input');
    await this._validateInput(utxo);
    this._inputs.push(utxo);
  };

  public addOutput = async (target: Target): Promise<void> => {
    await this._isSignedCheck('add output');
    await this._validateOutput(target);
    this._outputs.push(target);
  };

  public finalize = async (
    type: 'legacy' | 'segwit' | 'taproot' = 'segwit',
  ): Promise<void> => {
    await this._finalize(type);
  };

  public signAll = async (
    privkey: string,
    type: 'legacy' | 'segwit' | 'taproot' = 'segwit',
    timeLockScript = '',
    secretHex = '',
    sigHashType = '01000000',
  ): Promise<void> => {
    await Validator.validateKeyPair(
      '',
      privkey,
      type === 'taproot' ? 'schnorr' : 'ecdsa',
    );

    await this._finalize(type);
    // asynchronously sign all as index determined
    const promiseList: Promise<void>[] = [];
    for (let i = 0; i < this._inputs.length; i++) {
      promiseList.push(
        this.signInput(
          privkey,
          i,
          type,
          timeLockScript,
          secretHex,
          sigHashType,
        ),
      );
    }
    await Promise.all(promiseList);
  };

  public signInput = async (
    privkey: string,
    index: number,
    type: 'legacy' | 'segwit' | 'taproot' = 'segwit',
    timeLockScript = '',
    secretHex = '',
    sigHashType = '01000000',
  ): Promise<void> => {
    await this._validateInputRange(index);
    const pubkeyWithParityBit: string = await getPublicKey(privkey);
    const pubkey =
      type === 'taproot' ? pubkeyWithParityBit.slice(2) : pubkeyWithParityBit;
    await Validator.validateKeyPair(
      pubkey,
      privkey,
      type === 'taproot' ? 'schnorr' : 'ecdsa',
    );

    await this._finalize(type);
    await this._sign(
      [pubkey],
      [privkey],
      this._unsignedTx,
      index,
      false,
      timeLockScript,
      secretHex,
      type,
      sigHashType,
    );
  };

  public multiSignInput = async (
    pubkey: string[],
    privkey: string[],
    index: number,
    type: 'legacy' | 'segwit' = 'segwit',
    timeLockScript = '',
    secretHex = '',
    sigHashType = '01000000',
  ): Promise<void> => {
    await this._validateInputRange(index);
    await Validator.validateKeyPairBatch(pubkey, privkey, 'ecdsa');

    await this._finalize(type);
    await this._sign(
      pubkey,
      privkey,
      this._unsignedTx,
      index,
      true,
      timeLockScript,
      secretHex,
      type,
      sigHashType,
    );
  };

  public unlockHashInput = async (
    secretHex: string,
    index: number,
    type: 'legacy' | 'segwit' = 'segwit',
    timeLockScript = '',
  ): Promise<void> => {
    await this._validateInputRange(index);
    await this._finalize(type);
    // if not even, pad 0 at last
    secretHex.length % 2 !== 0 ? (secretHex += '0') : '';
    // script sig including secret and hash lock script
    const redeemScript =
      timeLockScript + (await generateHashLockScript(secretHex));
    const isSegwit = type === 'segwit' ? true : false;
    const scriptSig: string =
      '01' +
      Opcode.OP_1 + // as op_equalverify is used, trick to avoid clean stack err
      (isSegwit
        ? await getVarInt(secretHex.length / 2)
        : await pushData(secretHex)) +
      secretHex +
      (isSegwit
        ? await getVarInt(redeemScript.length / 2)
        : await pushData(redeemScript)) +
      redeemScript;
    isSegwit
      ? await this._setWitnessScript(
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
    const isSegwit: boolean = await this.isSegWit();
    // signed tx except witness and locktime
    // add witness field if exists
    let witness: string = '';
    // input count in varInt
    const inputCount: string = await getVarInt(this._inputs.length);
    let inputScript: string = inputCount;
    for (let i = 0; i < this._inputs.length; i++) {
      const inputScriptSingle: InputScript = this._inputScript.get(
        i,
      ) as InputScript;
      inputScript +=
        inputScriptSingle.txHash +
        inputScriptSingle.index +
        inputScriptSingle.scriptSig +
        inputScriptSingle.sequence;
      // push witness if exists('00' if not)
      witness += this._witness.has(i) ? this._witness.get(i) : '00';
    }
    const outputCount: string = await getVarInt(this._outputs.length);
    let outputScript: string = outputCount;
    for (let i: number = 0; i < this._outputs.length; i++) {
      const outputScriptSingle: OutputScript = this._outputScript.get(
        i,
      ) as OutputScript;
      outputScript +=
        outputScriptSingle.value + outputScriptSingle.scriptPubKey;
    }
    return (
      this._version +
      (isSegwit ? this._segWitMarker + this._segWitFlag : '') +
      inputScript +
      outputScript +
      (witness.length === this._inputs.length * 2 ? '' : witness) +
      this._locktime
    );
  };

  // below are for custom smart contract
  public getInputHashToSign = async (
    redeemScript: string,
    index: number,
    type: 'legacy' | 'segwit' | 'taproot' | 'tapscript' = 'segwit',
    sigHashType = '01000000',
    keyVersion = '00',
  ): Promise<Uint8Array> => {
    await this._validateInputRange(index);
    if (type === 'legacy') await Validator.validateRedeemScript(redeemScript);
    if (type === 'segwit') await Validator.validateWitnessScript(redeemScript);

    await this._finalize(type);
    // op_pushdata and length in hex
    const scriptCodeLength: string =
      type === 'segwit'
        ? await getVarInt(redeemScript.length / 2)
        : await pushData(redeemScript);
    // add script length except op_pushdata(will add after sign)
    const scriptCode: string =
      type === 'tapscript' || type === 'taproot'
        ? redeemScript
        : scriptCodeLength.length === 2 || type === 'segwit'
        ? scriptCodeLength + redeemScript
        : scriptCodeLength.slice(2) + redeemScript;

    return await this._getHashToSign(
      this._unsignedTx,
      index,
      scriptCode,
      type,
      sigHashType,
      keyVersion,
    );
  };

  public signInputByScriptSig = async (
    sigStack: string[],
    index: number,
    type: 'legacy' | 'segwit' | 'tapscript' = 'segwit',
  ): Promise<void> => {
    await this._validateInputRange(index);

    await this._finalize(type);
    if (type === 'segwit' || type === 'tapscript') {
      // witness stack item count (including redeem script)
      const witnessCount = await getVarInt(sigStack.length);
      let witnessScript = '';
      // encode bytes to read each witness item
      for (let i = 0; i < sigStack.length; i++) {
        // check witness stack item size
        if (type === 'segwit') await Validator.validateWitnessItem(sigStack[i]);
        witnessScript +=
          (await getVarInt(sigStack[i].length / 2)) + sigStack[i];
      }
      // check witness script size
      if (type === 'segwit')
        await Validator.validateWitnessScript(witnessScript);

      await this._setWitnessScript(index, witnessScript, witnessCount);
    } else {
      let scriptSig: string = '';
      // encode bytes to read each sig item
      for (let i = 0; i < sigStack.length - 1; i++) {
        scriptSig += (await pushData(sigStack[i])) + sigStack[i];
      }

      // check redeem script size
      const redeemScript: string = sigStack[sigStack.length - 1];
      await Validator.validateRedeemScript(redeemScript);

      scriptSig += (await pushData(redeemScript)) + redeemScript;
      // check script sig size
      await Validator.validateScriptSig(scriptSig);

      await this._setInputScriptSig(index, scriptSig);
    }
  };

  public getId = async (): Promise<string> => {
    // little endian of double sha256 serialized tx
    return bytesToHex(
      (await hash256(hexToBytes(await this._getSignedHexLegacy()))).reverse(),
    );
  };

  // must be set >= any of timelock input block height
  public setLocktime = async (block: number): Promise<void> => {
    await this._isSignedCheck('set locktime');
    await Validator.validateBlockLock(block);

    this._locktime = await reverseHex(await padZeroHexN(block.toString(16), 8));
  };

  public setVersion = async (version: number): Promise<void> => {
    await this._isSignedCheck('set version');
    this._version = await reverseHex(
      await padZeroHexN(version.toString(16), 8),
    );
  };

  public disableRBF = async (): Promise<void> => {
    await this._isSignedCheck('disable rbf');
    this._defaultSequence = 'feffffff';
  };

  public disableLocktime = async (): Promise<void> => {
    await this._isSignedCheck('disable locktime');
    this._defaultSequence = 'ffffffff';
  };

  public isSegWit = async (): Promise<boolean> => {
    return this._witness.size !== 0 ? true : false;
  };

  private _finalize = async (
    type: 'legacy' | 'segwit' | 'taproot' | 'tapscript',
  ): Promise<void> => {
    // if already finalized, just return
    if (this._unsignedTx.length !== 0) {
      if (type === 'legacy') return;
    } else {
      await Promise.all([this._finalizeInputs(), this._finalizeOutputs()]);
      // input count in varInt
      const inputCount: string = await getVarInt(this._inputs.length);
      let inputScript: string = inputCount;
      for (let i: number = 0; i < this._inputs.length; i++) {
        const inputScriptSingle: InputScript = this._inputScript.get(
          i,
        ) as InputScript;
        inputScript +=
          inputScriptSingle.txHash +
          inputScriptSingle.index +
          inputScriptSingle.scriptSig +
          inputScriptSingle.sequence;
      }
      const outputCount: string = await getVarInt(this._outputs.length);
      let outputScript: string = outputCount;
      for (let i: number = 0; i < this._outputs.length; i++) {
        const outputScriptSingle: OutputScript = this._outputScript.get(
          i,
        ) as OutputScript;
        outputScript +=
          outputScriptSingle.value + outputScriptSingle.scriptPubKey;
      }
      this._unsignedTx =
        this._version + inputScript + outputScript + this._locktime;
    }
    if (type !== 'legacy') await this._finalizeSegwit(type);
  };

  private _finalizeInputs = async (): Promise<void> => {
    // if already finalized, just return
    if (this._inputScript.size !== 0) return;

    // get input script hex
    for (let i = 0; i < this._inputs.length; i++) {
      /* 
      tx hash + tx index + empty script sig + sequence
      */
      const txHash: string = await reverseHex(this._inputs[i].txHash);
      const index: string = await reverseHex(
        await padZeroHexN(this._inputs[i].index.toString(16), 8),
      );
      // OP_0 will be replaced into scriptPubKey to sign
      const scriptSig: string = Opcode.OP_0;
      const sequence: string = this._inputs[i].sequence
        ? (this._inputs[i].sequence as string)
        : this._defaultSequence;
      // for segwit, little endian input amount list
      const amount: string = await reverseHex(
        await padZeroHexN((this._inputs[i].value as number).toString(16), 16),
      );
      this._inputScript.set(i, {
        txHash,
        index,
        scriptSig,
        sequence,
        amount,
      });
    }
  };

  private _finalizeOutputs = async (): Promise<void> => {
    // if already finalized, just return
    if (this._outputScript.size !== 0) return;
    // output count in varInt

    // get output script hex
    for (let i: number = 0; i < this._outputs.length; i++) {
      const value: string = await reverseHex(
        await padZeroHexN(this._outputs[i].value.toString(16), 16),
      );
      const scriptPubKey: string = this._outputs[i].address
        ? await getScriptByAddress(this._outputs[i].address as string)
        : (this._outputs[i].script as string);
      // value + scriptPubKey
      this._outputScript.set(i, {
        value: value,
        scriptPubKey: (await getVarInt(scriptPubKey.length / 2)) + scriptPubKey,
      });
    }
  };

  private _finalizeSegwit = async (
    type: 'segwit' | 'taproot' | 'tapscript',
  ): Promise<void> => {
    // if already finalized, just return
    if (this._witnessMsgPrefix.length !== 0 && type === 'segwit') return;
    const versionByte: Uint8Array = hexToBytes(this._version);
    let outpoint = '';
    let sequence = '';
    for (let i: number = 0; i < this._inputScript.size; i++) {
      const inputScriptSingle: InputScript = this._inputScript.get(
        i,
      ) as InputScript;
      outpoint += inputScriptSingle.txHash + inputScriptSingle.index;
      sequence += inputScriptSingle.sequence;
    }
    const prevHash: Uint8Array = await sha256(hexToBytes(outpoint));
    const sequenceHash: Uint8Array = await sha256(hexToBytes(sequence));
    this._witnessMsgPrefix = new Uint8Array([
      ...versionByte,
      ...(await sha256(prevHash)),
      ...(await sha256(sequenceHash)),
    ]);
    let outputScript = '';
    for (let i = 0; i < this._outputScript.size; i++) {
      const outputScriptSingle: OutputScript = this._outputScript.get(
        i,
      ) as OutputScript;
      outputScript +=
        outputScriptSingle.value + outputScriptSingle.scriptPubKey;
    }
    const outputHash: Uint8Array = await sha256(hexToBytes(outputScript));
    // below are little endians
    const lockTimeByte: Uint8Array = hexToBytes(this._locktime);
    this._witnessMsgSuffix = new Uint8Array([
      ...(await sha256(outputHash)),
      ...lockTimeByte,
    ]);

    // taproot
    // if already finalized, just return
    if (this._taprootMsgPrefix.length === 0 && type !== 'segwit')
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
    let amount = '';
    let scriptPubKeyJoined = '';
    for (let i: number = 0; i < this._inputScript.size; i++) {
      const inputScriptSingle: InputScript = this._inputScript.get(
        i,
      ) as InputScript;
      amount += inputScriptSingle.amount;
      if (!this._inputs[i].script)
        throw new Error('Script is required for taproot');
      scriptPubKeyJoined +=
        (await getVarInt((this._inputs[i].script?.length as number) / 2)) +
        this._inputs[i].script;
    }
    const valueHash: Uint8Array = await sha256(hexToBytes(amount));
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
    sigHashType = '01000000',
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
    const msgHash: Uint8Array = await this._getHashToSign(
      unsignedTx,
      inputIdx,
      scriptCode,
      type,
      sigHashType,
    );

    // get script sig to insert
    let scriptSig: string = '';
    if (!isMultiSig) {
      // p2pkh scrip sig
      const signature: string = await sign(
        msgHash,
        privkey[0],
        type !== 'taproot' ? 'ecdsa' : 'schnorr',
        sigHashType,
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
        const signature = await sign(msgHash, privkey[i], 'ecdsa', sigHashType);
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
      ? await this._setWitnessScript(
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
    inputIdx: number,
    scriptCode: string,
    type: 'legacy' | 'segwit' | 'taproot' | 'tapscript' = 'segwit',
    sigHashType = '01000000',
    keyVersion = '00',
  ): Promise<Uint8Array> => {
    if (type === 'taproot' || type === 'tapscript') {
      const epoch: number = 0;
      const spendType: number = type === 'taproot' ? 0 : 1 * 2; // no annex
      // little endian
      const inputIdxBytes: Uint8Array = await hexToBytes(
        await padZeroHexN(inputIdx.toString(16), 8),
      ).reverse();

      const sigMsg: Uint8Array = new Uint8Array([
        epoch,
        // schnorr use default sig hash
        sigHashType === '01000000' ? 0 : parseInt(sigHashType.slice(0, 2)),
        ...this._taprootMsgPrefix,
        spendType,
        ...inputIdxBytes,
      ]);

      return await getTapSigHash(
        type === 'taproot'
          ? sigMsg
          : new Uint8Array([
              ...sigMsg,
              ...(await getTapLeaf(scriptCode)),
              parseInt(keyVersion),
              ...(await hexToBytes('ffffffff')),
            ]),
      );
    } else if (type === 'segwit') {
      // below are little endians
      const inputScriptSingle: InputScript = this._inputScript.get(
        inputIdx,
      ) as InputScript;
      const outpointByte: Uint8Array = hexToBytes(
        inputScriptSingle.txHash + inputScriptSingle.index,
      );
      const scriptCodeByte: Uint8Array = hexToBytes(scriptCode);
      const valueByte: Uint8Array = hexToBytes(
        await padZeroHexN(this._inputs[inputIdx].value.toString(16), 16),
      ).reverse();
      const sequence: string = this._inputs[inputIdx].sequence
        ? (this._inputs[inputIdx].sequence as string)
        : this._defaultSequence;
      const sequenceByte: Uint8Array = hexToBytes(sequence);
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
      (await getVarInt(this._inputs.length)).length + // tx input count(varInt)
      (64 + 8 + 2 + 8) * index + // txid + tx index + empty script sig + sequence
      (64 + 8) // (txid + tx index) of first input
    );
  };

  private _setInputScriptSig = async (
    inputIdx: number,
    scriptSig: string,
  ): Promise<void> => {
    const finalInputScript: string =
      (await getVarInt(scriptSig.length / 2)) + scriptSig;
    // replace unsigned input into signed
    const unsignedInputScript: InputScript = this._inputScript.get(
      inputIdx,
    ) as InputScript;
    unsignedInputScript.scriptSig = finalInputScript;
    this._inputScript.set(inputIdx, unsignedInputScript);
  };

  private _setWitnessScript = async (
    index: number,
    witnessScript: string,
    itemCount: string,
  ): Promise<void> => {
    this._witness.set(index, itemCount + witnessScript);
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
    if (this._outputScript.size !== 0)
      throw new Error(`Cannot ${taskMsg} after any of input is signed`);
  };

  // signed tx except witness(to calculate txid)
  private _getSignedHexLegacy = async (): Promise<string> => {
    // input count in varInt
    const inputCount: string = await getVarInt(this._inputs.length);
    let inputScript: string = inputCount;
    for (let i = 0; i < this._inputs.length; i++) {
      const inputScriptSingle: InputScript = this._inputScript.get(
        i,
      ) as InputScript;
      inputScript +=
        inputScriptSingle.txHash +
        inputScriptSingle.index +
        inputScriptSingle.scriptSig +
        inputScriptSingle.sequence;
    }
    const outputCount: string = await getVarInt(this._outputs.length);
    let outputScript: string = outputCount;
    for (let i: number = 0; i < this._outputs.length; i++) {
      const outputScriptSingle: OutputScript = this._outputScript.get(
        i,
      ) as OutputScript;
      outputScript +=
        outputScriptSingle.value + outputScriptSingle.scriptPubKey;
    }
    return this._version + inputScript + outputScript + this._locktime;
  };
  // hex is not strictly checked as will be checked when finalize, for performance
  private _validateInput = async (input: UTXO): Promise<void> => {
    if (
      input.txHash.length !== 64 ||
      !Number.isInteger(Number('0x' + input.txHash))
    )
      throw new Error('Input tx hash must be 32 byte hex');
    if (
      input.index < 0 ||
      input.index > 0xffffffff ||
      !Number.isInteger(input.index)
    )
      throw new Error('Input index must be 4 byte uint');
    if (input.value < 0 || !Number.isInteger(input.value))
      throw new Error('Input value must be 8 byte uint');
    if (
      input.sequence &&
      (input.sequence.length !== 8 ||
        !Number.isInteger(Number('0x' + input.sequence)))
    )
      throw new Error('Input sequence must be 4 byte hex');
  };
  // address is not checked as will be checked when finalize, for performance
  private _validateOutput = async (output: Target): Promise<void> => {
    if (!output.address && !output.script)
      throw new Error('Either address or script must be given for output');
    if (output.value < 0 || !Number.isInteger(output.value))
      throw new Error('Output value must be 8 byte uint');
    if (output.script && output.script.length > 20000)
      throw new Error('Output script must be equal or less tan 10,000 bytes');
  };
  // check input range when sign
  private _validateInputRange = async (index: number): Promise<void> => {
    if (index > this._inputs.length - 1)
      throw new Error(
        `Out of range, tx contains only ${this._inputs.length} inputs`,
      );
  };
}
