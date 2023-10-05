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

  constructor() {
    this.inputs = [];
    this.outputs = [];
    this.version = "01000000";
    this.locktime = "00000000";
  }

  public addInput = async (utxo: UTXO): Promise<void> => {
    this.inputs.push(utxo);
  };

  public addOutput = async (target: Target): Promise<void> => {
    this.outputs.push(target);
  };

  public sign = async (pubkey: string, privkey: string): Promise<string> => {
    const inputScript: string[] = await this._finalizeInputs();
    const outputScript: string = await this._finalizeOutputs();
    return await this._sign(pubkey, privkey, inputScript, outputScript);
  };

  private _finalizeInputs = async (): Promise<string[]> => {
    let inputScriptArr: string[] = [];
    const inputCount: string = await this._getVarInt(this.inputs.length);
    inputScriptArr.push(inputCount);
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

      inputScriptArr.push(inputScript);
    }

    return inputScriptArr;
  };

  private _finalizeOutputs = async (): Promise<string> => {
    const outputCount: string = await this._getVarInt(this.outputs.length);
    let outputScript: string = "";
    for (const output of this.outputs) {
      outputScript +=
        (await this._bigToLitleEndian(
          await this._makeHexN(
            Math.round(output.amount * 10 ** 8).toString(16),
            16
          )
        )) + (await this._getScriptPubKey(output.address));
    }
    return outputCount + outputScript;
  };

  private _sign = async (
    pubkey: string,
    privkey: string,
    inputScriptArr: string[],
    outputScript: string
  ): Promise<string> => {
    const sigHashType: string = "01000000";
    const data: string =
      this.version +
      inputScriptArr.join("") +
      outputScript +
      this.locktime +
      sigHashType;
    for (let i = 0; i < this.inputs.length; i++) {
      const index: number =
        8 + inputScriptArr[0].length + (64 + 8 + 2 + 8) * i + (64 + 8);
      const p2pkh: string =
        "19" + // script length for p2pkh
        Opcode.OP_DUP +
        Opcode.OP_HASH160 +
        "14" + // anything smaller than 4c is byte length to read
        bytesToHex(ripemd160(sha256(hexToBytes(pubkey)))) +
        Opcode.OP_EQUALVERIFY +
        Opcode.OP_CHECKSIG;

      const msg: Uint8Array = sha256(
        sha256(hexToBytes(data.slice(0, index) + p2pkh + data.slice(index + 2)))
      );
      const signature: string =
        secp256k1.sign(msg, privkey).toDERHex() + sigHashType.slice(0, 2);

      const scriptSig: string =
        (signature.length / 2).toString(16) + signature + "21" + pubkey;
      const inputScript: string = inputScriptArr[i + 1];
      const finalInputScript: string =
        inputScript.slice(0, inputScript.length - 10) +
        (await this._getVarInt(scriptSig.length / 2)) +
        scriptSig +
        inputScript.slice(inputScript.length - 8);
      inputScriptArr.splice(i + 1, 1, finalInputScript);
    }

    return (
      this.version + inputScriptArr.join("") + outputScript + this.locktime
    );
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
    if (address.slice(0, 1) !== "D" || address.slice(0, 1) !== "n") {
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
