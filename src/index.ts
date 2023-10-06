import { secp256k1 } from "@noble/curves/secp256k1";
import { sha256 } from "@noble/hashes/sha256";
import { ripemd160 } from "@noble/hashes/ripemd160";
import { hexToBytes, bytesToHex } from "@noble/hashes/utils";
import bs58 from "bs58";
import Opcode from "./Opcode";

export interface UTXO {
  id: string;
  index: number;
}

export interface Target {
  address: string;
  amount: number;
}

export const generateAddress = async (
  pubkey: string,
  network = "mainnet"
): Promise<string> => {
  const pubkeyHash: Uint8Array = ripemd160(sha256(hexToBytes(pubkey)));
  const version: Uint8Array = new Uint8Array([
    network === "mainnet" ? 0x1e : 0x71,
  ]);
  const checksum: Uint8Array = sha256(
    sha256(new Uint8Array([...version, ...pubkeyHash]))
  ).slice(0, 4);

  const bs58encoded: string = bs58.encode(
    new Uint8Array([...version, ...pubkeyHash, ...checksum])
  );

  return bs58encoded;
};

export class Transaction {
  version: string;
  locktime: string;
  inputs: UTXO[];
  outputs: Target[];
  private _inputScriptArr: string[];
  private _outputScript: string;
  private _unsignedTx: string;

  constructor() {
    this.inputs = [];
    this.outputs = [];
    this.version = "01000000";
    this.locktime = "00000000";
    this._inputScriptArr = [];
    this._outputScript = "";
    this._unsignedTx = "";
  }

  public addInput = async (utxo: UTXO): Promise<void> => {
    this.inputs.push(utxo);
  };

  public addOutput = async (target: Target): Promise<void> => {
    this.outputs.push(target);
  };

  public signAll = async (pubkey: string, privkey: string): Promise<void> => {
    for (let i = 0; i < this.inputs.length; i++) {
      await this.signInput(pubkey, privkey, i);
    }
  };

  public signInput = async (
    pubkey: string,
    privkey: string,
    index: number
  ): Promise<void> => {
    const unsignedTx = await this._finalize();
    await this._sign(pubkey, privkey, unsignedTx, index);
  };

  public getSignedHex = async (): Promise<string> => {
    return (
      this.version +
      this._inputScriptArr.join("") +
      this._outputScript +
      this.locktime
    );
  };

  private _finalize = async (): Promise<string> => {
    // if already finalized, just return
    if (this._unsignedTx.length !== 0) return this._unsignedTx;

    const inputScript: string[] = await this._finalizeInputs();
    const outputScript: string = await this._finalizeOutputs();

    this._unsignedTx =
      this.version + inputScript.join("") + outputScript + this.locktime;

    return this._unsignedTx;
  };

  private _finalizeInputs = async (): Promise<string[]> => {
    // if already finalized, just return
    if (this._inputScriptArr.length !== 0) return this._inputScriptArr;
    // input count in varInt
    const inputCount: string = await this._getVarInt(this.inputs.length);
    this._inputScriptArr.push(inputCount);
    // get input script hex
    for (const input of this.inputs) {
      /* 
      tx id + tx index + separator + sequence
      */
      const inputScript: string =
        this._bigToLitleEndian(input.id) +
        (await this._bigToLitleEndian(
          await this._makeHexN(input.index.toString(16), 8)
        )) +
        "00" + // will be replaced into scriptPubKey to sign
        "ffffffff"; // disable locktime

      this._inputScriptArr.push(inputScript);
    }

    return this._inputScriptArr;
  };

  private _finalizeOutputs = async (): Promise<string> => {
    // if already finalized, just return
    if (this._outputScript.length !== 0) return this._outputScript;
    // output count in varInt
    const outputCount: string = await this._getVarInt(this.outputs.length);
    this._outputScript = outputCount;
    // get output script hex
    for (const output of this.outputs) {
      // amount + scriptPubKey
      this._outputScript +=
        (await this._bigToLitleEndian(
          await this._makeHexN(
            Math.round(output.amount * 10 ** 8).toString(16),
            16
          )
        )) + (await this._getScriptPubKey(output.address));
    }

    return this._outputScript;
  };

  private _sign = async (
    pubkey: string,
    privkey: string,
    unsignedTx: string,
    inputIdx: number
  ): Promise<void> => {
    const sigHashType: string = "01000000";
    const txToSign: string = unsignedTx + sigHashType;
    // index to insert script sig
    const index: number =
      8 + // tx version
      this._inputScriptArr[0].length + // tx input count(varInt)
      (64 + 8 + 2 + 8) * inputIdx + // txid + tx index + seperator + sequence
      (64 + 8); // (txid + tx index) of first input

    // default script sig type is p2pkh
    const p2pkh: string =
      "19" + // script length for p2pkh
      Opcode.OP_DUP +
      Opcode.OP_HASH160 +
      "14" + // anything smaller than 4c is byte length to read
      bytesToHex(ripemd160(sha256(hexToBytes(pubkey)))) +
      Opcode.OP_EQUALVERIFY +
      Opcode.OP_CHECKSIG;

    // sign to generate DER signature
    const msg: Uint8Array = sha256(
      sha256(
        hexToBytes(txToSign.slice(0, index) + p2pkh + txToSign.slice(index + 2))
      )
    );
    const signature: string =
      secp256k1.sign(msg, privkey).toDERHex() + sigHashType.slice(0, 2);

    // get final signed input script(p2pkh)
    const scriptSig: string =
      (signature.length / 2).toString(16) + signature + "21" + pubkey;
    const inputScript: string = this._inputScriptArr[inputIdx + 1];
    const finalInputScript: string =
      inputScript.slice(0, inputScript.length - 10) +
      (await this._getVarInt(scriptSig.length / 2)) +
      scriptSig +
      inputScript.slice(inputScript.length - 8);
    // replace unsigned input into signed
    this._inputScriptArr.splice(inputIdx + 1, 1, finalInputScript);
  };

  private _makeHexN = async (hex: string, n: number): Promise<string> => {
    return "0".repeat(n - hex.length) + hex;
  };

  private _bigToLitleEndian = async (hex: string): Promise<string> => {
    return bytesToHex(hexToBytes(hex).reverse());
  };

  private _getVarInt = async (int: number): Promise<string> => {
    if (int <= 252) {
      return await this._makeHexN(int.toString(16), 2);
    } else if (int <= 65535) {
      return (
        "FD" +
        (await this._bigToLitleEndian(
          await this._makeHexN(int.toString(16), 4)
        ))
      );
    } else if (int <= 4294967295) {
      return (
        "FE" +
        (await this._bigToLitleEndian(
          await this._makeHexN(int.toString(16), 8)
        ))
      );
    } else {
      return (
        "FF" +
        (await this._bigToLitleEndian(
          await this._makeHexN(int.toString(16), 16)
        ))
      );
    }
  };

  private _getScriptPubKey = async (address: string): Promise<string> => {
    if (
      address.slice(0, 1) === "9" ||
      address.slice(0, 1) === "A" ||
      address.slice(0, 1) === "2"
    ) {
      return (
        "17" + // script length for p2sh
        Opcode.OP_HASH160 +
        "14" + // anything smaller than 4c is byte length to read
        bytesToHex(bs58.decode(address).slice(1, 21)) +
        Opcode.OP_EQUAL
      );
    } else {
      // p2pkh default
      return (
        "19" + // script length for p2pkh
        Opcode.OP_DUP +
        Opcode.OP_HASH160 +
        "14" + // anything smaller than 4c is byte length to read
        bytesToHex(bs58.decode(address).slice(1, 21)) +
        Opcode.OP_EQUALVERIFY +
        Opcode.OP_CHECKSIG
      );
    }
  };
}
