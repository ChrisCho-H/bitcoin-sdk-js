import { hexToBytes, bytesToHex } from '@noble/hashes/utils';
import { Opcode } from './opcode.js';
import { hash256, sha256, sign } from './crypto.js';
import { padZeroHexN, reverseHex } from './encode.js';
import { getVarInt, pushData } from './data.js';
import { generateHashLockScript, generateMultiSigScript, generateSingleSigScript, getScriptByAddress, } from './script.js';
import { getTapLeaf, getTapSigHash } from './tapscript.js';
export class Transaction {
    _inputs;
    _outputs;
    _inputScript;
    _outputScript;
    _witness;
    _version = '01000000';
    _locktime = '00000000';
    _defaultSequence = 'fdffffff'; // enable locktime and rbf as default
    _unsignedTx = '';
    _segWitMarker = '00';
    _segWitFlag = '01';
    _witnessMsgPrefix;
    _witnessMsgSuffix;
    _taprootMsgPrefix;
    constructor() {
        this._inputs = [];
        this._outputs = [];
        this._witness = new Map();
        this._inputScript = new Map();
        this._outputScript = new Map();
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
    signAll = async (pubkey, privkey, type = 'segwit', timeLockScript = '', secretHex = '', sigHashType = '01000000') => {
        if (type !== 'taproot' && pubkey.length !== 66)
            throw new Error('pubkey must be compressed 33 bytes');
        if (privkey.length !== 64)
            throw new Error('privkey must be 32 bytes');
        // asynchronously sign all as index determined
        const promiseList = [];
        for (let i = 0; i < this._inputs.length; i++) {
            promiseList.push(this.signInput(pubkey, privkey, i, type, timeLockScript, secretHex, sigHashType));
        }
        await Promise.all(promiseList);
    };
    signInput = async (pubkey, privkey, index, type = 'segwit', timeLockScript = '', secretHex = '', sigHashType = '01000000') => {
        if (type !== 'taproot' && pubkey.length !== 66)
            throw new Error('pubkey must be compressed 33 bytes');
        if (privkey.length !== 64)
            throw new Error('privkey must be 32 bytes');
        const unsignedTx = await this._finalize();
        await this._sign([pubkey], [privkey], unsignedTx, index, false, timeLockScript, secretHex, type, sigHashType);
    };
    multiSignInput = async (pubkey, privkey, index, type = 'segwit', timeLockScript = '', secretHex = '', sigHashType = '01000000') => {
        const unsignedTx = await this._finalize();
        await this._sign(pubkey, privkey, unsignedTx, index, true, timeLockScript, secretHex, type, sigHashType);
    };
    unlockHashInput = async (secretHex, index, type = 'segwit', timeLockScript = '') => {
        if (index > this._inputs.length - 1)
            throw new Error(`Out of range, tx contains only ${this._inputs.length} inputs`);
        await this._finalize();
        // if not even, pad 0 at last
        secretHex.length % 2 !== 0 ? (secretHex += '0') : '';
        // script sig including secret and hash lock script
        const redeemScript = timeLockScript + (await generateHashLockScript(secretHex));
        const isSegWit = type === 'segwit' ? true : false;
        const scriptSig = '01' +
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
            ? await this._setWitnessScriptSig(index, scriptSig, await this._getWitnessItemCount(['count_for_OP_1'], [], false, timeLockScript, secretHex))
            : await this._setInputScriptSig(index, scriptSig);
    };
    getSignedHex = async () => {
        const isSegWit = await this.isSegWit();
        // signed tx except witness and locktime
        // add witness field if exists
        let witness = '';
        // input count in varInt
        const inputCount = await getVarInt(this._inputs.length);
        let inputScript = inputCount;
        for (let i = 0; i < this._inputs.length; i++) {
            const inputScriptSingle = this._inputScript.get(i);
            inputScript +=
                inputScriptSingle.txHash +
                    inputScriptSingle.index +
                    inputScriptSingle.scriptSig +
                    inputScriptSingle.sequence;
            // push witness if exists('00' if not)
            witness += this._witness.has(i) ? this._witness.get(i) : '00';
        }
        const outputCount = await getVarInt(this._outputs.length);
        let outputScript = outputCount;
        for (let i = 0; i < this._outputs.length; i++) {
            const outputScriptSingle = this._outputScript.get(i);
            outputScript +=
                outputScriptSingle.value + outputScriptSingle.scriptPubKey;
        }
        return (this._version +
            (isSegWit ? this._segWitMarker + this._segWitFlag : '') +
            inputScript +
            outputScript +
            (witness.length === this._inputs.length * 2 ? '' : witness) +
            this._locktime);
    };
    // below are for custom smart contract
    getInputHashToSign = async (redeemScript, index, type = 'segwit', sigHashType = '01000000', keyVersion = '00') => {
        const unsignedTx = await this._finalize();
        // op_pushdata and length in hex
        const scriptCodeLength = type === 'segwit'
            ? await getVarInt(redeemScript.length / 2)
            : await pushData(redeemScript);
        // add script length except op_pushdata(will add after sign)
        const scriptCode = type === 'tapscript' || type === 'taproot'
            ? redeemScript
            : scriptCodeLength.length === 2 || type === 'segwit'
                ? scriptCodeLength + redeemScript
                : scriptCodeLength.slice(2) + redeemScript;
        return await this._getHashToSign(unsignedTx, index, scriptCode, type, sigHashType, keyVersion);
    };
    signInputByScriptSig = async (sigStack, index, type = 'segwit') => {
        if (type === 'segwit' || type === 'tapscript') {
            // witness stack item count (including redeem script)
            const witnessCount = await getVarInt(sigStack.length);
            let scriptSig = '';
            // encode bytes to read each witness item
            for (let i = 0; i < sigStack.length; i++) {
                scriptSig += (await getVarInt(sigStack[i].length / 2)) + sigStack[i];
            }
            await this._setWitnessScriptSig(index, scriptSig, witnessCount);
        }
        else {
            let scriptSig = '';
            // encode bytes to read each sig item
            for (let i = 0; i < sigStack.length; i++) {
                scriptSig += (await pushData(sigStack[i])) + sigStack[i];
            }
            await this._setInputScriptSig(index, scriptSig);
        }
    };
    getId = async () => {
        // little endian of double sha256 serialized tx
        return bytesToHex((await hash256(hexToBytes(await this._getSignedHexLegacy()))).reverse());
    };
    // must be set >= any of timelock input block height
    setLocktime = async (block) => {
        await this._isSignedCheck('set locktime');
        this._locktime = await reverseHex(await padZeroHexN(block.toString(16), 8));
    };
    disableRBF = async () => {
        await this._isSignedCheck('disable rbf');
        this._defaultSequence = 'feffffff';
    };
    disableLocktime = async () => {
        await this._isSignedCheck('disable locktime');
        this._defaultSequence = 'ffffffff';
    };
    isSegWit = async () => {
        return this._witness.size !== 0 ? true : false;
    };
    _finalize = async () => {
        // if already finalized, just return
        if (this._unsignedTx.length !== 0)
            return this._unsignedTx;
        await Promise.all([this._finalizeInputs(), this._finalizeOutputs()]);
        await this._finalizeSegwit();
        // input count in varInt
        const inputCount = await getVarInt(this._inputs.length);
        let inputScript = inputCount;
        for (let i = 0; i < this._inputs.length; i++) {
            const inputScriptSingle = this._inputScript.get(i);
            inputScript +=
                inputScriptSingle.txHash +
                    inputScriptSingle.index +
                    inputScriptSingle.scriptSig +
                    inputScriptSingle.sequence;
        }
        const outputCount = await getVarInt(this._outputs.length);
        let outputScript = outputCount;
        for (let i = 0; i < this._outputs.length; i++) {
            const outputScriptSingle = this._outputScript.get(i);
            outputScript +=
                outputScriptSingle.value + outputScriptSingle.scriptPubKey;
        }
        this._unsignedTx =
            this._version + inputScript + outputScript + this._locktime;
        return this._unsignedTx;
    };
    _finalizeInputs = async () => {
        // if already finalized, just return
        if (this._inputScript.size !== 0)
            return;
        // get input script hex
        for (let i = 0; i < this._inputs.length; i++) {
            /*
            tx hash + tx index + empty script sig + sequence
            */
            const txHash = await reverseHex(this._inputs[i].txHash);
            const index = await reverseHex(await padZeroHexN(this._inputs[i].index.toString(16), 8));
            // OP_0 will be replaced into scriptPubKey to sign
            const scriptSig = Opcode.OP_0;
            const sequence = this._inputs[i].sequence
                ? this._inputs[i].sequence
                : this._defaultSequence;
            // for segwit, little endian input amount list
            const amount = await reverseHex(await padZeroHexN(Math.floor(this._inputs[i].value * 10 ** 8).toString(16), 16));
            this._inputScript.set(i, {
                txHash,
                index,
                scriptSig,
                sequence,
                amount,
            });
        }
    };
    _finalizeOutputs = async () => {
        // if already finalized, just return
        if (this._outputScript.size !== 0)
            return;
        // output count in varInt
        // get output script hex
        for (let i = 0; i < this._outputs.length; i++) {
            const value = await reverseHex(await padZeroHexN(Math.floor(this._outputs[i].value * 10 ** 8).toString(16), 16));
            const scriptPubKey = this._outputs[i].address
                ? await getScriptByAddress(this._outputs[i].address)
                : this._outputs[i].script;
            // value + scriptPubKey
            this._outputScript.set(i, {
                value: value,
                scriptPubKey: (await getVarInt(scriptPubKey.length / 2)) + scriptPubKey,
            });
        }
    };
    _finalizeSegwit = async () => {
        const versionByte = hexToBytes(this._version);
        let outpoint = '';
        let sequence = '';
        for (let i = 0; i < this._inputScript.size; i++) {
            const inputScriptSingle = this._inputScript.get(i);
            outpoint += inputScriptSingle.txHash + inputScriptSingle.index;
            sequence += inputScriptSingle.sequence;
        }
        const prevHash = await sha256(hexToBytes(outpoint));
        const sequenceHash = await sha256(hexToBytes(sequence));
        this._witnessMsgPrefix = new Uint8Array([
            ...versionByte,
            ...(await sha256(prevHash)),
            ...(await sha256(sequenceHash)),
        ]);
        let outputScript = '';
        for (let i = 0; i < this._outputScript.size; i++) {
            const outputScriptSingle = this._outputScript.get(i);
            outputScript +=
                outputScriptSingle.value + outputScriptSingle.scriptPubKey;
        }
        const outputHash = await sha256(hexToBytes(outputScript));
        // below are little endians
        const lockTimeByte = hexToBytes(this._locktime);
        this._witnessMsgSuffix = new Uint8Array([
            ...(await sha256(outputHash)),
            ...lockTimeByte,
        ]);
        // taproot
        await this._finalizeTaproot(versionByte, lockTimeByte, prevHash, sequenceHash, outputHash);
    };
    _finalizeTaproot = async (versionByte, lockTimeByte, prevHash, sequenceHash, outputHash) => {
        let amount = '';
        let scriptPubKeyJoined = '';
        for (let i = 0; i < this._inputScript.size; i++) {
            const inputScriptSingle = this._inputScript.get(i);
            amount += inputScriptSingle.amount;
            scriptPubKeyJoined +=
                (await getVarInt(this._inputs[i].script?.length / 2)) +
                    this._inputs[i].script;
        }
        const valueHash = await sha256(hexToBytes(amount));
        const scriptPubKeyHash = await sha256(hexToBytes(scriptPubKeyJoined));
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
    _sign = async (pubkey, privkey, unsignedTx, inputIdx, isMultiSig, timeLockScript = '', secretHex = '', type = 'segwit', sigHashType = '01000000') => {
        // get script pub key to sign
        let scriptCode = '';
        // if taproot, no need for script code
        if (type !== 'taproot') {
            // hash lock redeem script if unlock hash exists
            let hashLockScript = '';
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
            }
            else {
                // multi sig type of p2sh script
                const p2sh = await generateMultiSigScript(privkey.length, pubkey);
                scriptCode = timeLockScript + hashLockScript + p2sh;
            }
        }
        // op_pushdata and length in hex
        const scriptCodeLength = type !== 'legacy'
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
        const msgHash = await this._getHashToSign(unsignedTx, inputIdx, scriptCode, type, sigHashType);
        // get script sig to insert
        let scriptSig = '';
        if (!isMultiSig) {
            // p2pkh scrip sig
            const signature = await sign(msgHash, privkey[0], type !== 'taproot' ? 'ecdsa' : 'schnorr', sigHashType);
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
        }
        else {
            // p2sh script sig
            // multi sig for p2sh script
            let multiSig = Opcode.OP_0; //one extra unused value removed from the stack for OP_CHECKMULTISIG
            for (let i = 0; i < privkey.length; i++) {
                if (privkey[i].length !== 64)
                    throw new Error('privkey must be 32 bytes');
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
            ? await this._setWitnessScriptSig(inputIdx, scriptSig, type === 'taproot'
                ? '01'
                : await this._getWitnessItemCount(pubkey, privkey, isMultiSig, timeLockScript, secretHex))
            : await this._setInputScriptSig(inputIdx, scriptSig);
    };
    _getHashToSign = async (unsignedTx, inputIdx, scriptCode, type = 'segwit', sigHashType = '01000000', keyVersion = '00') => {
        // index to insert script sig
        if (inputIdx > this._inputs.length - 1)
            throw new Error(`Out of range, tx contains only ${this._inputs.length} inputs`);
        if (type === 'taproot' || type === 'tapscript') {
            const epoch = 0;
            const spendType = type === 'taproot' ? 0 : 1 * 2; // no annex
            // little endian
            const inputIdxBytes = await hexToBytes(await padZeroHexN(inputIdx.toString(16), 8)).reverse();
            const sigMsg = new Uint8Array([
                epoch,
                // schnorr use default sig hash
                sigHashType === '01000000' ? 0 : parseInt(sigHashType.slice(0, 2)),
                ...this._taprootMsgPrefix,
                spendType,
                ...inputIdxBytes,
            ]);
            return await getTapSigHash(type === 'taproot'
                ? sigMsg
                : new Uint8Array([
                    ...sigMsg,
                    ...(await getTapLeaf(scriptCode)),
                    parseInt(keyVersion),
                    ...(await hexToBytes('ffffffff')),
                ]));
        }
        else if (type === 'segwit') {
            // below are little endians
            const inputScriptSingle = this._inputScript.get(inputIdx);
            const outpointByte = hexToBytes(inputScriptSingle.txHash + inputScriptSingle.index);
            const scriptCodeByte = hexToBytes(scriptCode);
            const valueByte = hexToBytes(await padZeroHexN(Math.floor(this._inputs[inputIdx].value * 10 ** 8).toString(16), 16)).reverse();
            const sequence = this._inputs[inputIdx].sequence
                ? this._inputs[inputIdx].sequence
                : this._defaultSequence;
            const sequenceByte = hexToBytes(sequence);
            const sigHashByte = hexToBytes(sigHashType);
            return await hash256(new Uint8Array([
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
            return await hash256(hexToBytes(txToSign.slice(0, index) + scriptCode + txToSign.slice(index + 2)));
        }
    };
    _getScriptCodeIdx = async (index) => {
        return (8 + // tx version
            (await getVarInt(this._inputs.length)).length + // tx input count(varInt)
            (64 + 8 + 2 + 8) * index + // txid + tx index + empty script sig + sequence
            (64 + 8) // (txid + tx index) of first input
        );
    };
    _setInputScriptSig = async (inputIdx, scriptSig) => {
        if (scriptSig.length > 3300)
            throw new Error('script sig must be less than 1650 bytes');
        const finalInputScript = (await getVarInt(scriptSig.length / 2)) + scriptSig;
        // replace unsigned input into signed
        const unsignedInputScript = this._inputScript.get(inputIdx);
        unsignedInputScript.scriptSig = finalInputScript;
        this._inputScript.set(inputIdx, unsignedInputScript);
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
        return padZeroHexN(witnessCount.toString(16), 2);
    };
    _isSignedCheck = async (taskMsg) => {
        // if already finalized, at least one input is signed
        if (this._outputScript.size !== 0)
            throw new Error(`Cannot ${taskMsg} after any of input is signed`);
    };
    // signed tx except witness(to calculate txid)
    _getSignedHexLegacy = async () => {
        // input count in varInt
        const inputCount = await getVarInt(this._inputs.length);
        let inputScript = inputCount;
        for (let i = 0; i < this._inputs.length; i++) {
            const inputScriptSingle = this._inputScript.get(i);
            inputScript +=
                inputScriptSingle.txHash +
                    inputScriptSingle.index +
                    inputScriptSingle.scriptSig +
                    inputScriptSingle.sequence;
        }
        const outputCount = await getVarInt(this._outputs.length);
        let outputScript = outputCount;
        for (let i = 0; i < this._outputs.length; i++) {
            const outputScriptSingle = this._outputScript.get(i);
            outputScript +=
                outputScriptSingle.value + outputScriptSingle.scriptPubKey;
        }
        return this._version + inputScript + outputScript + this._locktime;
    };
}
