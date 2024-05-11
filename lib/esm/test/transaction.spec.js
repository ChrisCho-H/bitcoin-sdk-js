// tx
import * as assert from 'assert';
import { describe, it } from 'mocha';
import * as bitcoin from '../src/index.js';
describe('legacy transaction test', () => {
    it('p2pkh, p2wpkh, p2tr address must be generated', async () => {
        // Given
        const version = 1;
        const inputCount = 5;
        const txHash = await bitcoin.encode.bytesToHex(crypto.getRandomValues(new Uint8Array(32)));
        const index = Math.floor(Math.random() * (0xffffffff - inputCount - 0 + 1) + 0);
        const value = Math.random() * (Number.MAX_SAFE_INTEGER - 0 + 1) + 0;
        const keypair = await bitcoin.wallet.generateKeyPair();
        const locktime = Math.floor(Math.random() * (500000000 - 1 - 0 + 1) + 0);
        const secretHex = await bitcoin.encode.bytesToHex(crypto.getRandomValues(new Uint8Array(32)));
        const HTLC = bitcoin.Opcode.OP_IF +
            (await bitcoin.script.generateTimeLockScript(locktime)) +
            (await bitcoin.data.pushData(keypair.publicKey)) +
            keypair.publicKey +
            bitcoin.Opcode.OP_ELSE +
            (await bitcoin.script.generateHashLockScript(secretHex)) +
            (await bitcoin.data.pushData(keypair.publicKey)) +
            keypair.publicKey +
            bitcoin.Opcode.OP_ENDIF +
            bitcoin.Opcode.OP_CHECKSIG;
        // When
        const tx = new bitcoin.Transaction();
        await tx.setVersion(version);
        await tx.setLocktime(locktime);
        for (let i = 0; i < inputCount; i++)
            await tx.addInput({
                txHash: txHash,
                index: index + i,
                value: value,
            });
        // simple p2pkh address
        await tx.addOutput({
            address: await bitcoin.address.generateAddress(keypair.publicKey, 'legacy'),
            value: value,
        });
        // 2-of-3 multisig
        await tx.addOutput({
            address: await bitcoin.address.generateScriptAddress(await bitcoin.script.generateMultiSigScript(2, [
                keypair.publicKey,
                keypair.publicKey,
                keypair.publicKey,
            ]), 'legacy'),
            value: value,
        });
        // hash time lock without sig verification
        await tx.addOutput({
            address: await bitcoin.address.generateScriptAddress((await bitcoin.script.generateTimeLockScript(locktime)) +
                (await bitcoin.script.generateHashLockScript(secretHex)), 'legacy'),
            value: value,
        });
        // timelock + multisig 1-of-3
        await tx.addOutput({
            address: await bitcoin.address.generateScriptAddress((await bitcoin.script.generateTimeLockScript(locktime)) +
                (await bitcoin.script.generateMultiSigScript(1, [
                    keypair.publicKey,
                    keypair.publicKey,
                    keypair.publicKey,
                ])), 'legacy'),
            value: value,
        });
        // custom smart contract
        await tx.addOutput({
            address: await bitcoin.address.generateScriptAddress(HTLC, 'legacy'),
            value: value,
        });
        // sign input
        await tx.signInput(keypair.publicKey, keypair.privateKey, 0, 'legacy');
        await tx.multiSignInput([keypair.publicKey, keypair.publicKey, keypair.publicKey], [keypair.privateKey, keypair.privateKey], 1, 'legacy');
        await tx.unlockHashInput(secretHex, 2, 'legacy', await bitcoin.script.generateTimeLockScript(locktime));
        await tx.multiSignInput([keypair.publicKey, keypair.publicKey, keypair.publicKey], [keypair.privateKey], 3, 'legacy', await bitcoin.script.generateTimeLockScript(locktime));
        await tx.signInputByScriptSig([
            await bitcoin.crypto.sign(await tx.getInputHashToSign(HTLC, 3, 'legacy'), keypair.privateKey),
            secretHex,
            '',
            HTLC,
        ], 4, 'legacy');
        const txHex = await tx.getSignedHex();
        // Then
        // check transaction version
        let interpreterIndex = 0;
        assert.strictEqual(Number('0x' +
            (await bitcoin.encode.reverseHex(txHex.slice(interpreterIndex, (interpreterIndex += 8))))), version);
        // check transaction input count
        const inputCountVarInt = await bitcoin.data.getVarInt(inputCount);
        assert.strictEqual(inputCountVarInt, txHex.slice(interpreterIndex, (interpreterIndex += inputCountVarInt.length)));
        // check transaction input tx hash
        assert.strictEqual(await bitcoin.encode.reverseHex(txHash), txHex.slice(interpreterIndex, (interpreterIndex += 64)));
        // check transaction input index
        assert.strictEqual(index, Number('0x' +
            (await bitcoin.encode.reverseHex(txHex.slice(interpreterIndex, (interpreterIndex += 8))))));
        // check transaction locktime
        assert.strictEqual(Number('0x' + (await bitcoin.encode.reverseHex(txHex.slice(-8)))), locktime);
    });
});
describe('segwit transaction test', () => {
    it('p2pkh, p2wpkh, p2tr address must be generated', async () => {
        const version = 1;
        const txHash = await bitcoin.encode.bytesToHex(crypto.getRandomValues(new Uint8Array(32)));
        const index = Math.floor(Math.random() * (0xffffffff - 0 + 1) + 0);
        const value = Math.random() * (Number.MAX_SAFE_INTEGER - 0 + 1) + 0;
        const keypair = await bitcoin.wallet.generateKeyPair();
        const locktime = Math.floor(Math.random() * (500000000 - 1 - 0 + 1) + 0);
        const secretHex = await bitcoin.encode.bytesToHex(crypto.getRandomValues(new Uint8Array(32)));
        const HTLC = bitcoin.Opcode.OP_IF +
            (await bitcoin.script.generateTimeLockScript(locktime)) +
            (await bitcoin.data.pushData(keypair.publicKey)) +
            keypair.publicKey +
            bitcoin.Opcode.OP_ELSE +
            (await bitcoin.script.generateHashLockScript(secretHex)) +
            (await bitcoin.data.pushData(keypair.publicKey)) +
            keypair.publicKey +
            bitcoin.Opcode.OP_ENDIF +
            bitcoin.Opcode.OP_CHECKSIG;
        // When
        const tx = new bitcoin.Transaction();
        await tx.setVersion(version);
        await tx.setLocktime(locktime);
        for (let i = 0; i < 5; i++)
            await tx.addInput({
                txHash: txHash,
                index: index,
                value: value,
            });
        // simple p2pkh address
        await tx.addOutput({
            address: await bitcoin.address.generateAddress(keypair.publicKey, 'segwit'),
            value: value,
        });
        // 2-of-3 multisig
        await tx.addOutput({
            address: await bitcoin.address.generateScriptAddress(await bitcoin.script.generateMultiSigScript(2, [
                keypair.publicKey,
                keypair.publicKey,
                keypair.publicKey,
            ]), 'segwit'),
            value: value,
        });
        // hash time lock without sig verification
        await tx.addOutput({
            address: await bitcoin.address.generateScriptAddress((await bitcoin.script.generateTimeLockScript(locktime)) +
                (await bitcoin.script.generateHashLockScript(secretHex)), 'segwit'),
            value: value,
        });
        // timelock + multisig 1-of-3
        await tx.addOutput({
            address: await bitcoin.address.generateScriptAddress((await bitcoin.script.generateTimeLockScript(locktime)) +
                (await bitcoin.script.generateMultiSigScript(1, [
                    keypair.publicKey,
                    keypair.publicKey,
                    keypair.publicKey,
                ])), 'segwit'),
            value: value,
        });
        // custom smart contract
        await tx.addOutput({
            address: await bitcoin.address.generateScriptAddress(HTLC, 'segwit'),
            value: value,
        });
        // set lock time for timelock
        await tx.setLocktime(locktime);
        // sign input
        await tx.signInput(keypair.publicKey, keypair.privateKey, 0, 'segwit');
        await tx.multiSignInput([keypair.publicKey, keypair.publicKey, keypair.publicKey], [keypair.privateKey, keypair.privateKey], 1, 'segwit');
        await tx.unlockHashInput(secretHex, 2, 'segwit', await bitcoin.script.generateTimeLockScript(locktime));
        await tx.multiSignInput([keypair.publicKey, keypair.publicKey, keypair.publicKey], [keypair.privateKey], 3, 'segwit', await bitcoin.script.generateTimeLockScript(locktime));
        await tx.signInputByScriptSig([
            await bitcoin.crypto.sign(await tx.getInputHashToSign(HTLC, 3, 'segwit'), keypair.privateKey),
            secretHex,
            '',
            HTLC,
        ], 4, 'segwit');
        await tx.getSignedHex();
        await tx.getId();
    });
});
describe('taproot transaction test', () => {
    it('p2pkh, p2wpkh, p2tr address must be generated', async () => {
        // Given
        const txHash = await bitcoin.encode.bytesToHex(crypto.getRandomValues(new Uint8Array(32)));
        const index = Math.floor(Math.random() * (0xffffffff - 0 + 1) + 0);
        const value = Math.random() * (Number.MAX_SAFE_INTEGER - 0 + 1) + 0;
        const keypair = await bitcoin.wallet.generateKeyPair();
        const locktime = Math.floor(Math.random() * (500000000 - 1 - 0 + 1) + 0);
        const secretHex = await bitcoin.encode.bytesToHex(crypto.getRandomValues(new Uint8Array(32)));
        const HTLC = bitcoin.Opcode.OP_IF +
            (await bitcoin.script.generateTimeLockScript(locktime)) +
            (await bitcoin.data.pushData(keypair.publicKey)) +
            keypair.publicKey +
            bitcoin.Opcode.OP_ELSE +
            (await bitcoin.script.generateHashLockScript(secretHex)) +
            (await bitcoin.data.pushData(keypair.publicKey)) +
            keypair.publicKey +
            bitcoin.Opcode.OP_ENDIF +
            bitcoin.Opcode.OP_CHECKSIG;
        // When
        const tx = new bitcoin.Transaction();
        for (let i = 0; i < 5; i++)
            await tx.addInput({
                txHash: txHash,
                index: index,
                value: value,
            });
        // simple p2pkh address
        await tx.addOutput({
            address: await bitcoin.address.generateAddress(keypair.publicKey, 'segwit'),
            value: value,
        });
        // 2-of-3 multisig
        await tx.addOutput({
            address: await bitcoin.address.generateScriptAddress(await bitcoin.script.generateMultiSigScript(2, [
                keypair.publicKey,
                keypair.publicKey,
                keypair.publicKey,
            ]), 'segwit'),
            value: value,
        });
        // hash time lock without sig verification
        await tx.addOutput({
            address: await bitcoin.address.generateScriptAddress((await bitcoin.script.generateTimeLockScript(locktime)) +
                (await bitcoin.script.generateHashLockScript(secretHex)), 'segwit'),
            value: value,
        });
        // timelock + multisig 1-of-3
        await tx.addOutput({
            address: await bitcoin.address.generateScriptAddress((await bitcoin.script.generateTimeLockScript(locktime)) +
                (await bitcoin.script.generateMultiSigScript(1, [
                    keypair.publicKey,
                    keypair.publicKey,
                    keypair.publicKey,
                ])), 'segwit'),
            value: value,
        });
        // custom smart contract
        await tx.addOutput({
            address: await bitcoin.address.generateScriptAddress(HTLC, 'legacy'),
            value: value,
        });
        // set lock time for timelock
        await tx.setLocktime(locktime);
        // sign input
        await tx.signInput(keypair.publicKey, keypair.privateKey, 0, 'legacy');
        await tx.multiSignInput([keypair.publicKey, keypair.publicKey, keypair.publicKey], [keypair.privateKey, keypair.privateKey], 1, 'legacy');
        await tx.unlockHashInput(secretHex, 2, 'legacy', await bitcoin.script.generateTimeLockScript(locktime));
        await tx.multiSignInput([keypair.publicKey, keypair.publicKey, keypair.publicKey], [keypair.privateKey], 3, 'legacy', await bitcoin.script.generateTimeLockScript(locktime));
        await tx.signInputByScriptSig([
            await bitcoin.crypto.sign(await tx.getInputHashToSign(HTLC, 3), keypair.privateKey),
            secretHex,
            '',
            HTLC,
        ], 4);
        await tx.getSignedHex();
        await tx.getId();
    });
});
