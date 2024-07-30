import { padZeroHexN, reverseHex } from './encode.js';
import { Opcode } from './opcode.js';
import { Validator } from './validator.js';
export const getVarInt = async (num) => {
    await Validator.validateUint64(num);
    if (num <= 252) {
        return await padZeroHexN(num.toString(16), 2);
    }
    else if (num <= 65535) {
        return 'fd' + (await reverseHex(await padZeroHexN(num.toString(16), 4)));
    }
    else if (num <= 4294967295) {
        return 'fe' + (await reverseHex(await padZeroHexN(num.toString(16), 8)));
    }
    else {
        return 'ff' + (await reverseHex(await padZeroHexN(num.toString(16), 16)));
    }
};
export const pushData = async (data) => {
    await Validator.validateMinimalPush(data);
    return data.length / 2 < 76
        ? await padZeroHexN((data.length / 2).toString(16), 2)
        : data.length / 2 < 256
            ? Opcode.OP_PUSHDATA1 +
                (await padZeroHexN((data.length / 2).toString(16), 2))
            : Opcode.OP_PUSHDATA2 +
                (await reverseHex(await padZeroHexN((data.length / 2).toString(16), 4)));
};
export const varIntToNumber = async (varInt) => {
    if (varInt.length === 2) {
        return Number('0x' + varInt);
    }
    else {
        return Number('0x' + (await reverseHex(varInt.slice(2))));
    }
};
export const pushDataToNumber = async (pushData) => {
    if (pushData.length === 2) {
        return Number('0x' + pushData);
    }
    else {
        return Number('0x' + pushData.slice(2));
    }
};
