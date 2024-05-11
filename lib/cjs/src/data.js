"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.pushDataToNumber = exports.varIntToNumber = exports.pushData = exports.getVarInt = void 0;
const encode_js_1 = require("./encode.js");
const opcode_js_1 = require("./opcode.js");
const validator_js_1 = require("./validator.js");
const getVarInt = async (num) => {
    await validator_js_1.Validator.validateUint64(num);
    if (num <= 252) {
        return await (0, encode_js_1.padZeroHexN)(num.toString(16), 2);
    }
    else if (num <= 65535) {
        return 'fd' + (await (0, encode_js_1.reverseHex)(await (0, encode_js_1.padZeroHexN)(num.toString(16), 4)));
    }
    else if (num <= 4294967295) {
        return 'fe' + (await (0, encode_js_1.reverseHex)(await (0, encode_js_1.padZeroHexN)(num.toString(16), 8)));
    }
    else {
        return 'ff' + (await (0, encode_js_1.reverseHex)(await (0, encode_js_1.padZeroHexN)(num.toString(16), 16)));
    }
};
exports.getVarInt = getVarInt;
const pushData = async (data) => {
    await validator_js_1.Validator.validateMinimalPush(data);
    return data.length / 2 < 76
        ? await (0, encode_js_1.padZeroHexN)((data.length / 2).toString(16), 2)
        : data.length / 2 < 256
            ? opcode_js_1.Opcode.OP_PUSHDATA1 +
                (await (0, encode_js_1.padZeroHexN)((data.length / 2).toString(16), 2))
            : opcode_js_1.Opcode.OP_PUSHDATA2 +
                (await (0, encode_js_1.reverseHex)(await (0, encode_js_1.padZeroHexN)((data.length / 2).toString(16), 4)));
};
exports.pushData = pushData;
const varIntToNumber = async (varInt) => {
    if (varInt.length === 2) {
        return Number('0x' + varInt);
    }
    else {
        return Number('0x' + varInt.slice(2));
    }
};
exports.varIntToNumber = varIntToNumber;
const pushDataToNumber = async (pushData) => {
    if (pushData.length === 2) {
        return Number('0x' + pushData);
    }
    else {
        return Number('0x' + pushData.slice(2));
    }
};
exports.pushDataToNumber = pushDataToNumber;
