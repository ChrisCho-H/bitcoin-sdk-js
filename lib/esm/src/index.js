import { secp256k1 } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { ripemd160 } from '@noble/hashes/ripemd160';
import { hexToBytes, bytesToHex, utf8ToBytes } from '@noble/hashes/utils';
import bs58 from 'bs58';
import Opcode from './Opcode.js';
export const generateAddress = async (pubkey, network = 'mainnet') => {
    if (pubkey.length !== 66)
        throw new Error('pubkey must be compressed 33 bytes');
    const pubkeyHash = ripemd160(sha256(hexToBytes(pubkey)));
    const version = new Uint8Array([
        network === 'mainnet' ? 0x1e : 0x71,
    ]);
    const checksum = sha256(sha256(new Uint8Array([...version, ...pubkeyHash]))).slice(0, 4);
    const bs58encoded = bs58.encode(new Uint8Array([...version, ...pubkeyHash, ...checksum]));
    return bs58encoded;
};
export const generateSingleSigScript = async (pubkey) => {
    if (pubkey.length !== 66)
        throw new Error('pubkey must be compressed 33 bytes');
    return (Opcode.OP_DUP +
        Opcode.OP_HASH160 +
        '14' + // anything smaller than 4c is byte length to read
        bytesToHex(ripemd160(sha256(hexToBytes(pubkey)))) +
        Opcode.OP_EQUALVERIFY +
        Opcode.OP_CHECKSIG);
};
export const generateMultiSigScript = async (privkeyCount, pubkeys) => {
    if (privkeyCount > 15 || pubkeys.length > 15)
        throw new Error('Maximum number of keys is 15');
    const pubkeyJoin = '21' + // first pubkey bytes to read
        pubkeys.join('21'); // other pubkey and bytes to read
    if (pubkeyJoin.length / pubkeys.length !== 68)
        throw new Error('pubkey must be compressed 33 bytes');
    // multi sig type of p2sh script
    const p2sh = (80 + privkeyCount).toString(16) + // m signatures
        pubkeyJoin +
        (80 + pubkeys.length).toString(16) + // n pubkeys
        Opcode.OP_CHECKMULTISIG;
    return p2sh;
};
export const generateScriptAddress = async (script, network = 'mainnet') => {
    if (script.length > 1040)
        throw new Error('Redeem script must be less than 520 bytes');
    const scriptHash = ripemd160(sha256(hexToBytes(script)));
    const version = new Uint8Array([
        network === 'mainnet' ? 0x16 : 0xc4,
    ]);
    const checksum = sha256(sha256(new Uint8Array([...version, ...scriptHash]))).slice(0, 4);
    const bs58encoded = bs58.encode(new Uint8Array([...version, ...scriptHash, ...checksum]));
    return bs58encoded;
};
export const generateKeyPair = async () => {
    const privateKey = secp256k1.utils.randomPrivateKey();
    const publicKey = secp256k1.getPublicKey(privateKey);
    return {
        publicKey: bytesToHex(publicKey),
        privateKey: bytesToHex(privateKey),
    };
};
export const generateDataScript = async (dataToWrite, encode) => {
    const data = encode === 'hex' ? dataToWrite : bytesToHex(utf8ToBytes(dataToWrite));
    if (data.length > 160)
        throw new Error('Maximum data size is 80 bytes');
    return Opcode.OP_RETURN + (await _readBytesN(data)) + data;
};
export const generateTimeLockScript = async (block, utc, isAbsolute = true) => {
    if (!block && !utc)
        throw new Error('Either block or utc must be given for output');
    if (isAbsolute) {
        if (block && block >= 500000000)
            throw new Error('Block height must be < 500,000,000');
        if (utc && utc < 500000000)
            throw new Error('UTC must be >= 500,000,000');
    }
    else {
        if (block && block > 65535)
            throw new Error('Block height must be < 65,535');
        if (utc && utc > 33554430)
            throw new Error('UTC must be < 33,554,431');
        if (utc && utc % 512 !== 0)
            throw new Error('UTC must be mutiple of 512');
    }
    let locktime = block
        ? block.toString(16)
        : utc.toString(16);
    locktime.length % 2 !== 0 ? (locktime = '0' + locktime) : '';
    const opcode = isAbsolute
        ? Opcode.OP_CHECKLOCKTIMEVERIFY
        : Opcode.OP_CHECKSEQUENCEVERIFY;
    return ((await _readBytesN(locktime)) +
        (await _bigToLitleEndian(locktime)) +
        opcode +
        Opcode.OP_DROP);
};
export const generateHashLockScript = async (secretHex) => {
    // if not even, pad 0 at last
    secretHex.length % 2 !== 0 ? (secretHex += '0') : '';
    if (secretHex.length > 3200)
        throw new Error('script sig must be less than 1650 bytes');
    return (Opcode.OP_HASH256 +
        '20' +
        bytesToHex(sha256(sha256(hexToBytes(secretHex)))) +
        Opcode.OP_EQUAL);
};
export const getScriptByAddress = async (address, withLength = false) => {
    if (address.slice(0, 1) === '9' ||
        address.slice(0, 1) === 'A' ||
        address.slice(0, 1) === '2') {
        const length = withLength ? '17' : ''; // script length for p2sh
        return (length +
            Opcode.OP_HASH160 +
            '14' + // anything smaller than 4c is byte length to read
            bytesToHex(bs58.decode(address).slice(1, 21)) +
            Opcode.OP_EQUAL);
    }
    else {
        // p2pkh default
        const length = withLength ? '19' : ''; // script length for p2sh
        return (length +
            Opcode.OP_DUP +
            Opcode.OP_HASH160 +
            '14' + // anything smaller than 4c is byte length to read
            bytesToHex(bs58.decode(address).slice(1, 21)) +
            Opcode.OP_EQUALVERIFY +
            Opcode.OP_CHECKSIG);
    }
};
export class Transaction {
    _version;
    _locktime;
    _inputs;
    _outputs;
    _inputScriptArr;
    _outputScriptArr;
    _unsignedTx;
    _sequence;
    constructor() {
        this._inputs = [];
        this._outputs = [];
        this._version = '01000000';
        this._locktime = '00000000';
        this._inputScriptArr = [];
        this._outputScriptArr = [];
        this._unsignedTx = '';
        this._sequence = 'fdffffff'; // enable locktime and rbf as default
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
    signAll = async (pubkey, privkey) => {
        if (pubkey.length !== 66)
            throw new Error('pubkey must be compressed 33 bytes');
        if (privkey.length !== 64)
            throw new Error('privkey must be 32 bytes');
        for (let i = 0; i < this._inputs.length; i++) {
            await this.signInput(pubkey, privkey, i);
        }
    };
    signInput = async (pubkey, privkey, index, timeLockScript = '', secretHex = '') => {
        if (pubkey.length !== 66)
            throw new Error('pubkey must be compressed 33 bytes');
        if (privkey.length !== 64)
            throw new Error('privkey must be 32 bytes');
        const unsignedTx = await this._finalize();
        await this._sign([pubkey], [privkey], unsignedTx, index, false, timeLockScript, secretHex);
    };
    multiSignInput = async (pubkey, privkey, index, timeLockScript = '', secretHex = '') => {
        const unsignedTx = await this._finalize();
        await this._sign(pubkey, privkey, unsignedTx, index, true, timeLockScript, secretHex);
    };
    unlockHashInput = async (secretHex, index, timeLockScript = '') => {
        if (index > this._inputs.length - 1)
            throw new Error(`Out of range, tx contains only ${this._inputs.length} inputs`);
        await this._finalize();
        // if not even, pad 0 at last
        secretHex.length % 2 !== 0 ? (secretHex += '0') : '';
        // script sig including secret and hash lock script
        const redeemScript = timeLockScript + (await generateHashLockScript(secretHex));
        const scriptSig = (await _readBytesN(secretHex)) +
            secretHex +
            (await _readBytesN(redeemScript)) +
            redeemScript;
        await this._setInputScriptSig(index, scriptSig);
    };
    getSignedHex = async () => {
        return (this._version +
            this._inputScriptArr.join('') +
            this._outputScriptArr.join('') +
            this._locktime);
    };
    getId = async () => {
        // little endian of double sha256 serialized tx
        return bytesToHex(sha256(sha256(hexToBytes(await this.getSignedHex()))).reverse());
    };
    // must be set >= any of timelock input block height
    setLocktime = async (block) => {
        await this._isSignedCheck('set locktime');
        this._locktime = await _bigToLitleEndian(await _makeHexN(block.toString(16), 8));
    };
    disableRBF = async () => {
        await this._isSignedCheck('disable rbf');
        this._sequence = 'feffffff';
    };
    disableLocktime = async () => {
        await this._isSignedCheck('disable locktime');
        this._sequence = 'ffffffff';
    };
    _finalize = async () => {
        // if already finalized, just return
        if (this._unsignedTx.length !== 0)
            return this._unsignedTx;
        const inputScript = await this._finalizeInputs();
        const outputScript = await this._finalizeOutputs();
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
        const inputCount = await _getVarInt(this._inputs.length);
        this._inputScriptArr.push(inputCount);
        // get input script hex
        for (const input of this._inputs) {
            /*
            tx id + tx index + separator + sequence
            */
            const inputScript = (await _bigToLitleEndian(input.id)) +
                (await _bigToLitleEndian(await _makeHexN(input.index.toString(16), 8))) +
                Opcode.OP_0 + // will be replaced into scriptPubKey to sign
                this._sequence;
            this._inputScriptArr.push(inputScript);
        }
        return this._inputScriptArr;
    };
    _finalizeOutputs = async () => {
        // if already finalized, just return
        if (this._outputScriptArr.length !== 0)
            return this._outputScriptArr;
        // output count in varInt
        const outputCount = await _getVarInt(this._outputs.length);
        this._outputScriptArr.push(outputCount);
        // get output script hex
        for (const output of this._outputs) {
            // amount + scriptPubKey
            this._outputScriptArr.push((await _bigToLitleEndian(await _makeHexN(Math.floor(output.amount * 10 ** 8).toString(16), 16))) +
                (output.address
                    ? await getScriptByAddress(output.address, true)
                    : (await _getVarInt(output.script.length / 2)) +
                        output.script));
        }
        return this._outputScriptArr;
    };
    _sign = async (pubkey, privkey, unsignedTx, inputIdx, isMultiSig, timeLockScript = '', secretHex = '') => {
        const sigHashType = '01000000';
        const txToSign = unsignedTx + sigHashType;
        // index to insert script sig
        if (inputIdx > this._inputs.length - 1)
            throw new Error(`Out of range, tx contains only ${this._inputs.length} inputs`);
        const index = await this._getScriptCodeIdx(inputIdx);
        // get script pub key to sign
        let scriptCode = '';
        // op_pushdata and length in hex
        let scriptCodeLength = '';
        // hash lock redeem script if unlock hash exists
        let hashLockScript = '';
        if (secretHex.length !== 0) {
            hashLockScript =
                (await generateHashLockScript(secretHex)) + Opcode.OP_DROP;
            // if secretHex not even, pad 0 at last
            secretHex.length % 2 !== 0 ? (secretHex += '0') : '';
            // add bytes to read secretHex
            secretHex = (await _readBytesN(secretHex)) + secretHex;
        }
        if (!isMultiSig) {
            // default script sig type is p2pkh
            const p2pkh = await generateSingleSigScript(pubkey[0]);
            const script = timeLockScript + hashLockScript + p2pkh;
            scriptCodeLength = await _readBytesN(script);
            // add script length except op_pushdata(will add after sign)
            scriptCode =
                scriptCodeLength.length === 2
                    ? scriptCodeLength + script
                    : scriptCodeLength.slice(2) + script;
        }
        else {
            // multi sig type of p2sh script
            const p2sh = await generateMultiSigScript(privkey.length, pubkey);
            const script = timeLockScript + hashLockScript + p2sh;
            scriptCodeLength = await _readBytesN(script);
            // add script length except op_pushdata(will add after sign)
            scriptCode =
                scriptCodeLength.length === 2
                    ? scriptCodeLength + script
                    : scriptCodeLength.slice(2) + script;
        }
        // sign to generate DER signature
        const msg = sha256(sha256(hexToBytes(txToSign.slice(0, index) + scriptCode + txToSign.slice(index + 2))));
        // get script sig to insert
        let scriptSig = '';
        if (!isMultiSig) {
            // p2pkh scrip sig
            const signature = secp256k1.sign(msg, privkey[0]).toDERHex() + sigHashType.slice(0, 2);
            scriptSig +=
                (signature.length / 2).toString(16) +
                    signature +
                    '21' +
                    pubkey +
                    secretHex;
            if (timeLockScript.length !== 0 || secretHex.length !== 0)
                scriptSig +=
                    (scriptCodeLength.length !== 2 ? scriptCodeLength.slice(0, 2) : '') +
                        scriptCode;
        }
        else {
            // p2sh script sig
            // multi sig for p2sh script
            let multiSig = Opcode.OP_0; //one extra unused value removed from the stack for OP_CHECKMULTISIG
            for (let i = 0; i < privkey.length; i++) {
                if (privkey[i].length !== 64)
                    throw new Error('privkey must be 32 bytes');
                const signature = secp256k1.sign(msg, privkey[i]).toDERHex() + sigHashType.slice(0, 2);
                multiSig += (signature.length / 2).toString(16) + signature;
            }
            // scriptPubKey(redeem script) is in script sig
            scriptSig +=
                multiSig +
                    secretHex +
                    (scriptCodeLength.length !== 2 ? scriptCodeLength.slice(0, 2) : '') +
                    scriptCode;
        }
        await this._setInputScriptSig(inputIdx, scriptSig);
    };
    _getScriptCodeIdx = async (index) => {
        return (8 + // tx version
            this._inputScriptArr[0].length + // tx input count(varInt)
            (64 + 8 + 2 + 8) * index + // txid + tx index + seperator + sequence
            (64 + 8)); // (txid + tx index) of first input
    };
    _setInputScriptSig = async (index, scriptSig) => {
        if (scriptSig.length > 3300)
            throw new Error('script sig must be less than 1650 bytes');
        const inputScript = this._inputScriptArr[index + 1];
        const finalInputScript = inputScript.slice(0, inputScript.length - 10) +
            (await _getVarInt(scriptSig.length / 2)) +
            scriptSig +
            inputScript.slice(inputScript.length - 8);
        // replace unsigned input into signed
        this._inputScriptArr.splice(index + 1, 1, finalInputScript);
    };
    _isSignedCheck = async (taskMsg) => {
        // if already finalized, at least one input is signed
        if (this._outputScriptArr.length !== 0)
            throw new Error(`Cannot ${taskMsg} after any of input is signed`);
    };
}
const _makeHexN = async (hex, n) => {
    return '0'.repeat(n - hex.length) + hex;
};
const _bigToLitleEndian = async (hex) => {
    return bytesToHex(hexToBytes(hex).reverse());
};
const _getVarInt = async (int) => {
    if (int <= 252) {
        return await _makeHexN(int.toString(16), 2);
    }
    else if (int <= 65535) {
        return ('fd' + (await _bigToLitleEndian(await _makeHexN(int.toString(16), 4))));
    }
    else if (int <= 4294967295) {
        return ('fe' + (await _bigToLitleEndian(await _makeHexN(int.toString(16), 8))));
    }
    else {
        return ('ff' + (await _bigToLitleEndian(await _makeHexN(int.toString(16), 16))));
    }
};
const _readBytesN = async (dataToRead) => {
    return dataToRead.length / 2 < 76
        ? await _makeHexN((dataToRead.length / 2).toString(16), 2)
        : dataToRead.length / 2 < 256
            ? Opcode.OP_PUSHDATA1 +
                (await _makeHexN((dataToRead.length / 2).toString(16), 2))
            : Opcode.OP_PUSHDATA2 +
                (await _bigToLitleEndian(await _makeHexN((dataToRead.length / 2).toString(16), 4)));
};
