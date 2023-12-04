"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.Transaction = exports.generateDataScript = exports.generateKeyPair = exports.generateScriptAddress = exports.generateMultiSigScript = exports.generateAddress = void 0;
const secp256k1_1 = require("@noble/curves/secp256k1");
const sha256_1 = require("@noble/hashes/sha256");
const ripemd160_1 = require("@noble/hashes/ripemd160");
const utils_1 = require("@noble/hashes/utils");
const bs58_1 = __importDefault(require("bs58"));
const Opcode_js_1 = __importDefault(require("./Opcode.js"));
const generateAddress = async (pubkey, network = "mainnet") => {
    const pubkeyHash = (0, ripemd160_1.ripemd160)((0, sha256_1.sha256)((0, utils_1.hexToBytes)(pubkey)));
    const version = new Uint8Array([
        network === "mainnet" ? 0x1e : 0x71,
    ]);
    const checksum = (0, sha256_1.sha256)((0, sha256_1.sha256)(new Uint8Array([...version, ...pubkeyHash]))).slice(0, 4);
    const bs58encoded = bs58_1.default.encode(new Uint8Array([...version, ...pubkeyHash, ...checksum]));
    return bs58encoded;
};
exports.generateAddress = generateAddress;
const generateMultiSigScript = async (privkeyNums, pubkey) => {
    if (privkeyNums > 15 || pubkey.length > 15)
        throw new Error("Maximum number of keys is 15");
    // multi sig type of p2sh script
    const p2sh = (80 + privkeyNums).toString(16) + // m signatures
        "21" + // first pubkey bytes to read
        pubkey.join("21") + // other pubkey and bytes to read
        (80 + pubkey.length).toString(16) + // n pubkeys
        Opcode_js_1.default.OP_CHECKMULTISIG;
    return p2sh;
};
exports.generateMultiSigScript = generateMultiSigScript;
const generateScriptAddress = async (script, network = "mainnet") => {
    const scriptHash = (0, ripemd160_1.ripemd160)((0, sha256_1.sha256)((0, utils_1.hexToBytes)(script)));
    const version = new Uint8Array([
        network === "mainnet" ? 0x16 : 0xc4,
    ]);
    const checksum = (0, sha256_1.sha256)((0, sha256_1.sha256)(new Uint8Array([...version, ...scriptHash]))).slice(0, 4);
    const bs58encoded = bs58_1.default.encode(new Uint8Array([...version, ...scriptHash, ...checksum]));
    return bs58encoded;
};
exports.generateScriptAddress = generateScriptAddress;
const generateKeyPair = async () => {
    const privateKey = secp256k1_1.secp256k1.utils.randomPrivateKey();
    const publicKey = secp256k1_1.secp256k1.getPublicKey(privateKey);
    return {
        publicKey: (0, utils_1.bytesToHex)(publicKey),
        privateKey: (0, utils_1.bytesToHex)(privateKey),
    };
};
exports.generateKeyPair = generateKeyPair;
const generateDataScript = async (dataToWrite, encode) => {
    const data = encode === 'hex' ? dataToWrite : (0, utils_1.bytesToHex)((0, utils_1.utf8ToBytes)(dataToWrite));
    if (data.length > 160)
        throw new Error('Maximum data size is 80 bytes');
    return Opcode_js_1.default.OP_RETURN + await _readBytesN(data) + data;
};
exports.generateDataScript = generateDataScript;
class Transaction {
    _version;
    _locktime;
    _inputs;
    _outputs;
    _inputScriptArr;
    _outputScript;
    _unsignedTx;
    constructor() {
        this._inputs = [];
        this._outputs = [];
        this._version = "01000000";
        this._locktime = "00000000";
        this._inputScriptArr = [];
        this._outputScript = "";
        this._unsignedTx = "";
    }
    addInput = async (utxo) => {
        this._inputs.push(utxo);
    };
    addOutput = async (target) => {
        if (!target.address && !target.script)
            throw new Error('Either address or script must be given for output');
        this._outputs.push(target);
    };
    signAll = async (pubkey, privkey) => {
        for (let i = 0; i < this._inputs.length; i++) {
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
        return (this._version +
            this._inputScriptArr.join("") +
            this._outputScript +
            this._locktime);
    };
    _finalize = async () => {
        // if already finalized, just return
        if (this._unsignedTx.length !== 0)
            return this._unsignedTx;
        const inputScript = await this._finalizeInputs();
        const outputScript = await this._finalizeOutputs();
        this._unsignedTx =
            this._version + inputScript.join("") + outputScript + this._locktime;
        return this._unsignedTx;
    };
    _finalizeInputs = async () => {
        // if already finalized, just return
        if (this._inputScriptArr.length !== 0)
            return this._inputScriptArr;
        // input count in varInt
        const inputCount = await _getVarInt(this._inputs.length);
        this._inputScriptArr.push(inputCount);
        // get input script hex
        for (const input of this._inputs) {
            /*
            tx id + tx index + separator + sequence
            */
            const inputScript = await _bigToLitleEndian(input.id) +
                (await _bigToLitleEndian(await _makeHexN(input.index.toString(16), 8))) +
                Opcode_js_1.default.OP_0 + // will be replaced into scriptPubKey to sign
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
        const outputCount = await _getVarInt(this._outputs.length);
        this._outputScript = outputCount;
        // get output script hex
        for (const output of this._outputs) {
            // amount + scriptPubKey
            this._outputScript +=
                (await _bigToLitleEndian(await _makeHexN(Math.floor(output.amount * 10 ** 8).toString(16), 16))) + (output.address ? (await this._getScriptPubKey(output.address))
                    : (await _getVarInt(output.script.length / 2) + output.script));
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
                    Opcode_js_1.default.OP_DUP +
                    Opcode_js_1.default.OP_HASH160 +
                    "14" + // anything smaller than 4c is byte length to read
                    (0, utils_1.bytesToHex)((0, ripemd160_1.ripemd160)((0, sha256_1.sha256)((0, utils_1.hexToBytes)(pubkey[0])))) +
                    Opcode_js_1.default.OP_EQUALVERIFY +
                    Opcode_js_1.default.OP_CHECKSIG;
        }
        else {
            // multi sig type of p2sh script
            const p2sh = await (0, exports.generateMultiSigScript)(privkey.length, pubkey);
            // add script length except op_pushdata(will add after sign)
            redeemScriptPrefix = await this._getRedeemScriptPrefix(p2sh);
            scriptCode = redeemScriptPrefix[1] + p2sh;
        }
        // sign to generate DER signature
        const msg = (0, sha256_1.sha256)((0, sha256_1.sha256)((0, utils_1.hexToBytes)(txToSign.slice(0, index) + scriptCode + txToSign.slice(index + 2))));
        // get script sig to insert
        let scriptSig = "";
        if (!isMultiSig) {
            // p2pkh scrip sig
            const signature = secp256k1_1.secp256k1.sign(msg, privkey[0]).toDERHex() + sigHashType.slice(0, 2);
            scriptSig +=
                (signature.length / 2).toString(16) + signature + "21" + pubkey;
        }
        else {
            // p2sh script sig
            // multi sig for p2sh script
            let multiSig = Opcode_js_1.default.OP_0; //one extra unused value removed from the stack for OP_CHECKMULTISIG
            for (let i = 0; i < privkey.length; i++) {
                const signature = secp256k1_1.secp256k1.sign(msg, privkey[i]).toDERHex() + sigHashType.slice(0, 2);
                multiSig += (signature.length / 2).toString(16) + signature;
            }
            // scriptPubKey(redeem script) is in script sig
            scriptSig = multiSig + redeemScriptPrefix[0] + scriptCode;
        }
        const inputScript = this._inputScriptArr[inputIdx + 1];
        const finalInputScript = inputScript.slice(0, inputScript.length - 10) +
            (await _getVarInt(scriptSig.length / 2)) +
            scriptSig +
            inputScript.slice(inputScript.length - 8);
        // replace unsigned input into signed
        this._inputScriptArr.splice(inputIdx + 1, 1, finalInputScript);
    };
    _getScriptPubKey = async (address) => {
        if (address.slice(0, 1) === "9" ||
            address.slice(0, 1) === "A" ||
            address.slice(0, 1) === "2") {
            return ("17" + // script length for p2sh
                Opcode_js_1.default.OP_HASH160 +
                "14" + // anything smaller than 4c is byte length to read
                (0, utils_1.bytesToHex)(bs58_1.default.decode(address).slice(1, 21)) +
                Opcode_js_1.default.OP_EQUAL);
        }
        else {
            // p2pkh default
            return ("19" + // script length for p2pkh
                Opcode_js_1.default.OP_DUP +
                Opcode_js_1.default.OP_HASH160 +
                "14" + // anything smaller than 4c is byte length to read
                (0, utils_1.bytesToHex)(bs58_1.default.decode(address).slice(1, 21)) +
                Opcode_js_1.default.OP_EQUALVERIFY +
                Opcode_js_1.default.OP_CHECKSIG);
        }
    };
    _getRedeemScriptPrefix = async (redeemScript) => {
        return redeemScript.length / 2 < 76
            ? ["", await _getVarInt(redeemScript.length / 2)]
            : redeemScript.length / 2 < 256
                ? [
                    Opcode_js_1.default.OP_PUSHDATA1,
                    await _makeHexN((redeemScript.length / 2).toString(16), 2),
                ]
                : [
                    Opcode_js_1.default.OP_PUSHDATA2,
                    await _bigToLitleEndian(await _makeHexN((redeemScript.length / 2).toString(16), 4)),
                ];
    };
}
exports.Transaction = Transaction;
const _makeHexN = async (hex, n) => {
    return "0".repeat(n - hex.length) + hex;
};
const _bigToLitleEndian = async (hex) => {
    return (0, utils_1.bytesToHex)((0, utils_1.hexToBytes)(hex).reverse());
};
const _getVarInt = async (int) => {
    if (int <= 252) {
        return await _makeHexN(int.toString(16), 2);
    }
    else if (int <= 65535) {
        return ("fd" +
            (await _bigToLitleEndian(await _makeHexN(int.toString(16), 4))));
    }
    else if (int <= 4294967295) {
        return ("fe" +
            (await _bigToLitleEndian(await _makeHexN(int.toString(16), 8))));
    }
    else {
        return ("ff" +
            (await _bigToLitleEndian(await _makeHexN(int.toString(16), 16))));
    }
};
const _readBytesN = async (dataToRead) => {
    return dataToRead.length / 2 < 76 ?
        await _makeHexN((dataToRead.length / 2).toString(16), 2)
        : dataToRead.length / 2 < 256 ?
            Opcode_js_1.default.OP_PUSHDATA1 + await _makeHexN((dataToRead.length / 2).toString(16), 2)
            : Opcode_js_1.default.OP_PUSHDATA2 + await _bigToLitleEndian(await _makeHexN((dataToRead.length / 2).toString(16), 4));
};
