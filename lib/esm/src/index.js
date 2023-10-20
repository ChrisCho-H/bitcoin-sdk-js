import { secp256k1 } from "@noble/curves/secp256k1";
import { sha256 } from "@noble/hashes/sha256";
import { ripemd160 } from "@noble/hashes/ripemd160";
import { hexToBytes, bytesToHex } from "@noble/hashes/utils";
import bs58 from "bs58";
import Opcode from "./Opcode.js";
export const generateAddress = async (pubkey, network = "mainnet") => {
    const pubkeyHash = ripemd160(sha256(hexToBytes(pubkey)));
    const version = new Uint8Array([
        network === "mainnet" ? 0x1e : 0x71,
    ]);
    const checksum = sha256(sha256(new Uint8Array([...version, ...pubkeyHash]))).slice(0, 4);
    const bs58encoded = bs58.encode(new Uint8Array([...version, ...pubkeyHash, ...checksum]));
    return bs58encoded;
};
export const generateMultiSigScript = async (privkeyNums, pubkey) => {
    if (privkeyNums > 15 || pubkey.length > 15)
        throw new Error("Maximum number of keys is 15");
    // multi sig type of p2sh script
    const p2sh = (80 + privkeyNums).toString(16) + // m signatures
        "21" + // first pubkey bytes to read
        pubkey.join("21") + // other pubkey and bytes to read
        (80 + pubkey.length).toString(16) + // n pubkeys
        Opcode.OP_CHECKMULTISIG;
    return p2sh;
};
export const generateScriptAddress = async (script, network = "mainnet") => {
    const scriptHash = ripemd160(sha256(hexToBytes(script)));
    const version = new Uint8Array([
        network === "mainnet" ? 0x16 : 0xc4,
    ]);
    const checksum = sha256(sha256(new Uint8Array([...version, ...scriptHash]))).slice(0, 4);
    const bs58encoded = bs58.encode(new Uint8Array([...version, ...scriptHash, ...checksum]));
    return bs58encoded;
};
export class Transaction {
    version;
    locktime;
    inputs;
    outputs;
    _inputScriptArr;
    _outputScript;
    _unsignedTx;
    constructor() {
        this.inputs = [];
        this.outputs = [];
        this.version = "01000000";
        this.locktime = "00000000";
        this._inputScriptArr = [];
        this._outputScript = "";
        this._unsignedTx = "";
    }
    addInput = async (utxo) => {
        this.inputs.push(utxo);
    };
    addOutput = async (target) => {
        this.outputs.push(target);
    };
    signAll = async (pubkey, privkey) => {
        for (let i = 0; i < this.inputs.length; i++) {
            await this.signInput(pubkey, privkey, i);
        }
    };
    signInput = async (pubkey, privkey, index) => {
        const unsignedTx = await this._finalize();
        await this._sign([pubkey], [privkey], unsignedTx, index);
    };
    multiSignInput = async (pubkey, privkey, index) => {
        const unsignedTx = await this._finalize();
        await this._sign(pubkey, privkey, unsignedTx, index, true);
    };
    getSignedHex = async () => {
        return (this.version +
            this._inputScriptArr.join("") +
            this._outputScript +
            this.locktime);
    };
    _finalize = async () => {
        // if already finalized, just return
        if (this._unsignedTx.length !== 0)
            return this._unsignedTx;
        const inputScript = await this._finalizeInputs();
        const outputScript = await this._finalizeOutputs();
        this._unsignedTx =
            this.version + inputScript.join("") + outputScript + this.locktime;
        return this._unsignedTx;
    };
    _finalizeInputs = async () => {
        // if already finalized, just return
        if (this._inputScriptArr.length !== 0)
            return this._inputScriptArr;
        // input count in varInt
        const inputCount = await this._getVarInt(this.inputs.length);
        this._inputScriptArr.push(inputCount);
        // get input script hex
        for (const input of this.inputs) {
            /*
            tx id + tx index + separator + sequence
            */
            const inputScript = this._bigToLitleEndian(input.id) +
                (await this._bigToLitleEndian(await this._makeHexN(input.index.toString(16), 8))) +
                Opcode.OP_0 + // will be replaced into scriptPubKey to sign
                "ffffffff"; // disable locktime
            this._inputScriptArr.push(inputScript);
        }
        return this._inputScriptArr;
    };
    _finalizeOutputs = async () => {
        // if already finalized, just return
        if (this._outputScript.length !== 0)
            return this._outputScript;
        // output count in varInt
        const outputCount = await this._getVarInt(this.outputs.length);
        this._outputScript = outputCount;
        // get output script hex
        for (const output of this.outputs) {
            // amount + scriptPubKey
            this._outputScript +=
                (await this._bigToLitleEndian(await this._makeHexN(Math.floor(output.amount * 10 ** 8).toString(16), 16))) + (await this._getScriptPubKey(output.address));
        }
        return this._outputScript;
    };
    _sign = async (pubkey, privkey, unsignedTx, inputIdx, isMultiSig) => {
        const sigHashType = "01000000";
        const txToSign = unsignedTx + sigHashType;
        // index to insert script sig
        const index = 8 + // tx version
            this._inputScriptArr[0].length + // tx input count(varInt)
            (64 + 8 + 2 + 8) * inputIdx + // txid + tx index + seperator + sequence
            (64 + 8); // (txid + tx index) of first input
        // get script pub key to sign
        let scriptCode = "";
        // op_pushdata and length in hex
        let redeemScriptPrefix = [];
        if (!isMultiSig) {
            // default script sig type is p2pkh
            scriptCode =
                "19" + // script length for p2pkh
                    Opcode.OP_DUP +
                    Opcode.OP_HASH160 +
                    "14" + // anything smaller than 4c is byte length to read
                    bytesToHex(ripemd160(sha256(hexToBytes(pubkey[0])))) +
                    Opcode.OP_EQUALVERIFY +
                    Opcode.OP_CHECKSIG;
        }
        else {
            // multi sig type of p2sh script
            const p2sh = await generateMultiSigScript(privkey.length, pubkey);
            // add script length except op_pushdata(will add after sign)
            redeemScriptPrefix = await this._getRedeemScriptPrefix(p2sh);
            scriptCode = redeemScriptPrefix[1] + p2sh;
        }
        // sign to generate DER signature
        const msg = sha256(sha256(hexToBytes(txToSign.slice(0, index) + scriptCode + txToSign.slice(index + 2))));
        // get script sig to insert
        let scriptSig = "";
        if (!isMultiSig) {
            // p2pkh scrip sig
            const signature = secp256k1.sign(msg, privkey[0]).toDERHex() + sigHashType.slice(0, 2);
            scriptSig +=
                (signature.length / 2).toString(16) + signature + "21" + pubkey;
        }
        else {
            // p2sh script sig
            // multi sig for p2sh script
            let multiSig = Opcode.OP_0; //one extra unused value removed from the stack for OP_CHECKMULTISIG
            for (let i = 0; i < privkey.length; i++) {
                const signature = secp256k1.sign(msg, privkey[i]).toDERHex() + sigHashType.slice(0, 2);
                multiSig += (signature.length / 2).toString(16) + signature;
            }
            // scriptPubKey(redeem script) is in script sig
            scriptSig = multiSig + redeemScriptPrefix[0] + scriptCode;
        }
        const inputScript = this._inputScriptArr[inputIdx + 1];
        const finalInputScript = inputScript.slice(0, inputScript.length - 10) +
            (await this._getVarInt(scriptSig.length / 2)) +
            scriptSig +
            inputScript.slice(inputScript.length - 8);
        // replace unsigned input into signed
        this._inputScriptArr.splice(inputIdx + 1, 1, finalInputScript);
    };
    _makeHexN = async (hex, n) => {
        return "0".repeat(n - hex.length) + hex;
    };
    _bigToLitleEndian = async (hex) => {
        return bytesToHex(hexToBytes(hex).reverse());
    };
    _getVarInt = async (int) => {
        if (int <= 252) {
            return await this._makeHexN(int.toString(16), 2);
        }
        else if (int <= 65535) {
            return ("fd" +
                (await this._bigToLitleEndian(await this._makeHexN(int.toString(16), 4))));
        }
        else if (int <= 4294967295) {
            return ("fe" +
                (await this._bigToLitleEndian(await this._makeHexN(int.toString(16), 8))));
        }
        else {
            return ("ff" +
                (await this._bigToLitleEndian(await this._makeHexN(int.toString(16), 16))));
        }
    };
    _getScriptPubKey = async (address) => {
        if (address.slice(0, 1) === "9" ||
            address.slice(0, 1) === "A" ||
            address.slice(0, 1) === "2") {
            return ("17" + // script length for p2sh
                Opcode.OP_HASH160 +
                "14" + // anything smaller than 4c is byte length to read
                bytesToHex(bs58.decode(address).slice(1, 21)) +
                Opcode.OP_EQUAL);
        }
        else {
            // p2pkh default
            return ("19" + // script length for p2pkh
                Opcode.OP_DUP +
                Opcode.OP_HASH160 +
                "14" + // anything smaller than 4c is byte length to read
                bytesToHex(bs58.decode(address).slice(1, 21)) +
                Opcode.OP_EQUALVERIFY +
                Opcode.OP_CHECKSIG);
        }
    };
    _getRedeemScriptPrefix = async (redeemScript) => {
        return redeemScript.length / 2 < 76
            ? ["", await this._getVarInt(redeemScript.length / 2)]
            : redeemScript.length / 2 < 256
                ? [
                    Opcode.OP_PUSHDATA1,
                    await this._makeHexN((redeemScript.length / 2).toString(16), 2),
                ]
                : [
                    Opcode.OP_PUSHDATA2,
                    await this._bigToLitleEndian(await this._makeHexN((redeemScript.length / 2).toString(16), 4)),
                ];
    };
}
