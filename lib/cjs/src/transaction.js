"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Transaction = void 0;
const secp256k1_1 = require("@noble/curves/secp256k1");
const utils_1 = require("@noble/hashes/utils");
const opcode_js_1 = require("./opcode.js");
const crypto_js_1 = require("./crypto.js");
const encode_js_1 = require("./encode.js");
const data_js_1 = require("./data.js");
const script_js_1 = require("./script.js");
const tapscript_js_1 = require("./tapscript.js");
class Transaction {
    _version;
    _locktime;
    _inputs;
    _outputs;
    _inputScriptArr;
    _outputScriptArr;
    _inputAmountArr;
    _unsignedTx;
    _sequence;
    _segWitMarker = '00';
    _segWitFlag = '01';
    _witness;
    _witnessMsgPrefix;
    _witnessMsgSuffix;
    _taprootMsgPrefix;
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
        this._witness = new Map();
        this._witnessMsgPrefix = new Uint8Array(); // before outpoint
        this._witnessMsgSuffix = new Uint8Array(); // after sequence
        this._taprootMsgPrefix = new Uint8Array(); // before
    }
    addInput = async (utxo) => {
        await this._isSignedCheck('add input');
        this._inputs.push(utxo);
    };
    addOutput = async (target) => {
        await this._isSignedCheck('add output');
        if (!target.address && !target.script)
            throw new Error('Either address or script must be given for output');
        if (target.script && target.script.length > 20000)
            throw new Error('Output script must be less than 10k bytes');
        this._outputs.push(target);
    };
    signAll = async (pubkey, privkey, type = 'segwit', timeLockScript = '', secretHex = '') => {
        if (pubkey.length !== 66)
            throw new Error('pubkey must be compressed 33 bytes');
        if (privkey.length !== 64)
            throw new Error('privkey must be 32 bytes');
        for (let i = 0; i < this._inputs.length; i++) {
            await this.signInput(pubkey, privkey, i, type, timeLockScript, secretHex);
        }
    };
    signInput = async (pubkey, privkey, index, type = 'segwit', timeLockScript = '', secretHex = '') => {
        if (type !== 'taproot' && pubkey.length !== 66)
            throw new Error('pubkey must be compressed 33 bytes');
        if (type === 'taproot' && pubkey.length !== 0)
            throw new Error('schnorr pubkey is not required for taproot');
        if (privkey.length !== 64)
            throw new Error('privkey must be 32 bytes');
        const unsignedTx = await this._finalize();
        await this._sign([pubkey], [privkey], unsignedTx, index, false, timeLockScript, secretHex, type);
    };
    multiSignInput = async (pubkey, privkey, index, type = 'segwit', timeLockScript = '', secretHex = '') => {
        const unsignedTx = await this._finalize();
        await this._sign(pubkey, privkey, unsignedTx, index, true, timeLockScript, secretHex, type);
    };
    unlockHashInput = async (secretHex, index, type = 'segwit', timeLockScript = '') => {
        if (index > this._inputs.length - 1)
            throw new Error(`Out of range, tx contains only ${this._inputs.length} inputs`);
        await this._finalize();
        // if not even, pad 0 at last
        secretHex.length % 2 !== 0 ? (secretHex += '0') : '';
        // script sig including secret and hash lock script
        const redeemScript = timeLockScript + (await (0, script_js_1.generateHashLockScript)(secretHex));
        const isSegWit = type === 'segwit' ? true : false;
        const scriptSig = '01' +
            opcode_js_1.Opcode.OP_1 + // as op_equalverify is used, trick to avoid clean stack err
            (isSegWit
                ? await (0, data_js_1.getVarInt)(secretHex.length / 2)
                : await (0, data_js_1.pushData)(secretHex)) +
            secretHex +
            (isSegWit
                ? await (0, data_js_1.getVarInt)(redeemScript.length / 2)
                : await (0, data_js_1.pushData)(redeemScript)) +
            redeemScript;
        isSegWit
            ? await this._setWitnessScriptSig(index, scriptSig, await this._getWitnessItemCount(['count_for_OP_1'], [], false, timeLockScript, secretHex))
            : await this._setInputScriptSig(index, scriptSig);
    };
    getSignedHex = async () => {
        const isSegWit = await this.isSegWit();
        // signed tx except witness and locktime
        // add witness field if exists
        let witness = '';
        for (let i = 0; i < this._inputScriptArr.length - 1; i++) {
            // push witness if exists('00' if not)
            witness += this._witness.has(i) ? this._witness.get(i) : '00';
        }
        return (this._version +
            (isSegWit ? this._segWitMarker + this._segWitFlag : '') +
            this._inputScriptArr.join('') +
            this._outputScriptArr.join('') +
            (witness.length === this._inputs.length * 2 ? '' : witness) +
            this._locktime);
    };
    // below are for custom smart contract
    getInputHashToSign = async (redeemScript, index, type = 'segwit') => {
        const unsignedTx = await this._finalize();
        const sigHashType = '01000000';
        // op_pushdata and length in hex
        const scriptCodeLength = type === 'segwit'
            ? await (0, data_js_1.getVarInt)(redeemScript.length / 2)
            : await (0, data_js_1.pushData)(redeemScript);
        // add script length except op_pushdata(will add after sign)
        const scriptCode = scriptCodeLength.length === 2 || type === 'segwit'
            ? scriptCodeLength + redeemScript
            : scriptCodeLength.slice(2) + redeemScript;
        return await this._getHashToSign(unsignedTx, sigHashType, index, scriptCode, type);
    };
    signInputByScriptSig = async (sigList, redeemScript, index, type = 'segwit') => {
        if (type === 'segwit') {
            // witness stack item count (including redeem script)
            const witnessCount = await (0, data_js_1.getVarInt)(sigList.length + 1);
            let scriptSig = '';
            // encode bytes to read each witness item
            for (let i = 0; i < sigList.length; i++) {
                scriptSig += (await (0, data_js_1.getVarInt)(sigList[i].length / 2)) + sigList[i];
            }
            // encode bytes to read redeem script
            scriptSig += (await (0, data_js_1.getVarInt)(redeemScript.length / 2)) + redeemScript;
            await this._setWitnessScriptSig(index, scriptSig, witnessCount);
        }
        else {
            let scriptSig = '';
            // encode bytes to read each sig item
            for (let i = 0; i < sigList.length; i++) {
                scriptSig += (await (0, data_js_1.pushData)(sigList[i])) + sigList[i];
            }
            // encode bytes to read redeem script
            scriptSig += (await (0, data_js_1.pushData)(redeemScript)) + redeemScript;
            await this._setInputScriptSig(index, scriptSig);
        }
    };
    getId = async () => {
        // little endian of double sha256 serialized tx
        return (0, utils_1.bytesToHex)((await (0, crypto_js_1.hash256)((0, utils_1.hexToBytes)(await this.getSignedHex()))).reverse());
    };
    // must be set >= any of timelock input block height
    setLocktime = async (block) => {
        await this._isSignedCheck('set locktime');
        this._locktime = await (0, encode_js_1.reverseHex)(await (0, encode_js_1.padZeroHexN)(block.toString(16), 8));
    };
    disableRBF = async () => {
        await this._isSignedCheck('disable rbf');
        this._sequence = 'feffffff';
    };
    disableLocktime = async () => {
        await this._isSignedCheck('disable locktime');
        this._sequence = 'ffffffff';
    };
    isSegWit = async () => {
        return this._witness.size !== 0 ? true : false;
    };
    _finalize = async () => {
        // if already finalized, just return
        if (this._unsignedTx.length !== 0)
            return this._unsignedTx;
        const inputScript = await this._finalizeInputs();
        const outputScript = await this._finalizeOutputs();
        await this._finalizeSegwit();
        this._unsignedTx =
            this._version +
                inputScript.join('') +
                outputScript.join('') +
                this._locktime;
        return this._unsignedTx;
    };
    _finalizeInputs = async () => {
        // if already finalized, just return
        if (this._inputScriptArr.length !== 0)
            return this._inputScriptArr;
        // input count in varInt
        const inputCount = await (0, data_js_1.getVarInt)(this._inputs.length);
        this._inputScriptArr.push(inputCount);
        // get input script hex
        for (const input of this._inputs) {
            /*
            tx id + tx index + empty script sig + sequence
            */
            const inputScript = (await (0, encode_js_1.reverseHex)(input.id)) +
                (await (0, encode_js_1.reverseHex)(await (0, encode_js_1.padZeroHexN)(input.index.toString(16), 8))) +
                opcode_js_1.Opcode.OP_0 + // will be replaced into scriptPubKey to sign
                this._sequence;
            // for segwit, little endian input amount list
            const inputAmount = await (0, encode_js_1.reverseHex)(await (0, encode_js_1.padZeroHexN)(Math.floor(input.value * 10 ** 8).toString(16), 16));
            this._inputScriptArr.push(inputScript);
            this._inputAmountArr.push(inputAmount);
        }
        return this._inputScriptArr;
    };
    _finalizeOutputs = async () => {
        // if already finalized, just return
        if (this._outputScriptArr.length !== 0)
            return this._outputScriptArr;
        // output count in varInt
        const outputCount = await (0, data_js_1.getVarInt)(this._outputs.length);
        this._outputScriptArr.push(outputCount);
        // get output script hex
        for (const output of this._outputs) {
            const value = await (0, encode_js_1.reverseHex)(await (0, encode_js_1.padZeroHexN)(Math.floor(output.value * 10 ** 8).toString(16), 16));
            const scriptPubKey = output.address
                ? await (0, script_js_1.getScriptByAddress)(output.address)
                : output.script;
            // value + scriptPubKey
            this._outputScriptArr.push(value + (await (0, data_js_1.getVarInt)(scriptPubKey.length / 2)) + scriptPubKey);
        }
        return this._outputScriptArr;
    };
    _finalizeSegwit = async () => {
        const versionByte = (0, utils_1.hexToBytes)(this._version);
        const prevHash = await (0, crypto_js_1.sha256)((0, utils_1.hexToBytes)(this._inputScriptArr
            .reduce((accumulator, currentValue) => accumulator + currentValue.slice(0, 72), '')
            .slice(2)));
        const sequenceHash = await (0, crypto_js_1.sha256)((0, utils_1.hexToBytes)(this._sequence.repeat(this._inputs.length)));
        this._witnessMsgPrefix = new Uint8Array([
            ...versionByte,
            ...(await (0, crypto_js_1.sha256)(prevHash)),
            ...(await (0, crypto_js_1.sha256)(sequenceHash)),
        ]);
        const outputHash = await (0, crypto_js_1.sha256)((0, utils_1.hexToBytes)(this._outputScriptArr.join('').slice(2)));
        // below are little endians
        const lockTimeByte = (0, utils_1.hexToBytes)(this._locktime);
        this._witnessMsgSuffix = new Uint8Array([
            ...(await (0, crypto_js_1.sha256)(outputHash)),
            ...lockTimeByte,
        ]);
        // taproot
        await this._finalizeTaproot(versionByte, lockTimeByte, prevHash, sequenceHash, outputHash);
    };
    _finalizeTaproot = async (versionByte, lockTimeByte, prevHash, sequenceHash, outputHash) => {
        const valueHash = await (0, crypto_js_1.sha256)((0, utils_1.hexToBytes)(this._inputAmountArr.join('')));
        let scriptPubKeyJoined = '';
        for (const input of this._inputs) {
            scriptPubKeyJoined +=
                (await (0, data_js_1.getVarInt)(input.script?.length / 2)) + input.script;
        }
        const scriptPubKeyHash = await (0, crypto_js_1.sha256)((0, utils_1.hexToBytes)(scriptPubKeyJoined));
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
    _sign = async (pubkey, privkey, unsignedTx, inputIdx, isMultiSig, timeLockScript = '', secretHex = '', type = 'segwit') => {
        // get script pub key to sign
        let scriptCode = '';
        // if taproot, no need for script code
        if (type !== 'taproot') {
            // hash lock redeem script if unlock hash exists
            let hashLockScript = '';
            if (secretHex.length !== 0) {
                hashLockScript = await (0, script_js_1.generateHashLockScript)(secretHex);
                // if secretHex not even, pad 0 at last
                secretHex.length % 2 !== 0 ? (secretHex += '0') : '';
                // add bytes to read secretHex
                secretHex =
                    (type !== 'legacy'
                        ? await (0, data_js_1.getVarInt)(secretHex.length / 2)
                        : await (0, data_js_1.pushData)(secretHex)) + secretHex;
            }
            if (!isMultiSig) {
                // default script sig type is p2pkh
                const p2pkh = await (0, script_js_1.generateSingleSigScript)(pubkey[0]);
                scriptCode = timeLockScript + hashLockScript + p2pkh;
            }
            else {
                // multi sig type of p2sh script
                const p2sh = await (0, script_js_1.generateMultiSigScript)(privkey.length, pubkey);
                scriptCode = timeLockScript + hashLockScript + p2sh;
            }
        }
        // op_pushdata and length in hex
        const scriptCodeLength = type !== 'legacy'
            ? await (0, data_js_1.getVarInt)(scriptCode.length / 2)
            : await (0, data_js_1.pushData)(scriptCode);
        // add script length except op_pushdata(will add after sign)
        if (type !== 'taproot') {
            scriptCode =
                scriptCodeLength.length === 2 || type !== 'legacy'
                    ? scriptCodeLength + scriptCode
                    : scriptCodeLength.slice(2) + scriptCode;
        }
        // get msg hash to sign and generate DER signature
        const sigHashType = '01000000';
        const msgHash = await this._getHashToSign(unsignedTx, sigHashType, inputIdx, scriptCode, type);
        // get script sig to insert
        let scriptSig = '';
        if (!isMultiSig) {
            // p2pkh scrip sig
            const signature = await (0, crypto_js_1.sign)(msgHash, privkey[0], sigHashType, type !== 'taproot' ? 'secp256k1' : 'schnorr');
            scriptSig +=
                (signature.length / 2).toString(16) +
                    signature +
                    (type !== 'taproot'
                        ? (await (0, data_js_1.pushData)(pubkey[0])) + pubkey[0] + secretHex
                        : '');
            // scriptPubKey(redeem script) is in script sig if p2sh
            if (timeLockScript.length !== 0 || secretHex.length !== 0)
                scriptSig +=
                    (scriptCodeLength.length !== 2 && type === 'legacy'
                        ? scriptCodeLength.slice(0, 2)
                        : '') + scriptCode; // pushdata
        }
        else {
            // p2sh script sig
            // multi sig for p2sh script
            let multiSig = opcode_js_1.Opcode.OP_0; //one extra unused value removed from the stack for OP_CHECKMULTISIG
            for (let i = 0; i < privkey.length; i++) {
                if (privkey[i].length !== 64)
                    throw new Error('privkey must be 32 bytes');
                const signature = secp256k1_1.secp256k1.sign(msgHash, privkey[i]).toDERHex() +
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
            ? await this._setWitnessScriptSig(inputIdx, scriptSig, type === 'taproot'
                ? '01'
                : await this._getWitnessItemCount(pubkey, privkey, isMultiSig, timeLockScript, secretHex))
            : await this._setInputScriptSig(inputIdx, scriptSig);
    };
    _getHashToSign = async (unsignedTx, sigHashType, inputIdx, scriptCode, type = 'segwit') => {
        // index to insert script sig
        if (inputIdx > this._inputs.length - 1)
            throw new Error(`Out of range, tx contains only ${this._inputs.length} inputs`);
        if (type === 'taproot') {
            const epoch = 0;
            const spendType = 0; // no annex
            // little endian
            const inputIdxBytes = await (0, utils_1.hexToBytes)(await (0, encode_js_1.padZeroHexN)(inputIdx.toString(16), 8)).reverse();
            return await (0, tapscript_js_1.getTapSigHash)(new Uint8Array([
                epoch,
                parseInt(sigHashType.slice(0, 2)),
                ...this._taprootMsgPrefix,
                spendType,
                ...inputIdxBytes,
            ]));
        }
        else if (type === 'segwit') {
            // below are little endians
            const outpointByte = (0, utils_1.hexToBytes)(this._inputScriptArr[inputIdx + 1].slice(0, 72));
            const scriptCodeByte = (0, utils_1.hexToBytes)(scriptCode);
            const valueByte = (0, utils_1.hexToBytes)(await (0, encode_js_1.padZeroHexN)(Math.floor(this._inputs[inputIdx].value * 10 ** 8).toString(16), 16)).reverse();
            const sequenceByte = (0, utils_1.hexToBytes)(this._sequence);
            const sigHashByte = (0, utils_1.hexToBytes)(sigHashType);
            return await (0, crypto_js_1.hash256)(new Uint8Array([
                ...this._witnessMsgPrefix,
                ...outpointByte,
                ...scriptCodeByte,
                ...valueByte,
                ...sequenceByte,
                ...this._witnessMsgSuffix,
                ...sigHashByte,
            ]));
        }
        else {
            const txToSign = unsignedTx + sigHashType;
            const index = await this._getScriptCodeIdx(inputIdx);
            return await (0, crypto_js_1.hash256)((0, utils_1.hexToBytes)(txToSign.slice(0, index) + scriptCode + txToSign.slice(index + 2)));
        }
    };
    _getScriptCodeIdx = async (index) => {
        return (8 + // tx version
            this._inputScriptArr[0].length + // tx input count(varInt)
            (64 + 8 + 2 + 8) * index + // txid + tx index + empty script sig + sequence
            (64 + 8) // (txid + tx index) of first input
        );
    };
    _setInputScriptSig = async (index, scriptSig) => {
        if (scriptSig.length > 3300)
            throw new Error('script sig must be less than 1650 bytes');
        const inputScript = this._inputScriptArr[index + 1];
        const finalInputScript = inputScript.slice(0, inputScript.length - 10) +
            (await (0, data_js_1.getVarInt)(scriptSig.length / 2)) +
            scriptSig +
            inputScript.slice(inputScript.length - 8);
        // replace unsigned input into signed
        this._inputScriptArr.splice(index + 1, 1, finalInputScript);
    };
    _setWitnessScriptSig = async (index, witnessScriptSig, itemCount) => {
        if (witnessScriptSig.length > 20000)
            throw new Error('witness script must be less than 10,000 bytes');
        this._witness.set(index, itemCount + witnessScriptSig);
    };
    _getWitnessItemCount = async (pubkey, privkey, isMultiSig, timeLockScript = '', secretHex = '') => {
        let witnessCount = privkey.length; // signature count
        secretHex.length !== 0 ? (witnessCount += 1) : ''; // hash count
        isMultiSig
            ? (witnessCount += 2) // include OP_0 and redeem script
            : timeLockScript.length !== 0
                ? (witnessCount += 1) // include redeem script only
                : secretHex.length !== 0
                    ? (witnessCount += 1) // include redeem script only
                    : '';
        !isMultiSig ? (witnessCount += pubkey.length) : ''; // pubkey count
        return (0, encode_js_1.padZeroHexN)(witnessCount.toString(16), 2);
    };
    _isSignedCheck = async (taskMsg) => {
        // if already finalized, at least one input is signed
        if (this._outputScriptArr.length !== 0)
            throw new Error(`Cannot ${taskMsg} after any of input is signed`);
    };
}
exports.Transaction = Transaction;
