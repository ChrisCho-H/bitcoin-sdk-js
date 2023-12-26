"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.pushData = exports.getVarInt = void 0;
const encode_js_1 = require("./encode.js");
const opcode_js_1 = require("./opcode.js");
const getVarInt = async (int) => {
    if (int <= 252) {
        return await (0, encode_js_1.padZeroHexN)(int.toString(16), 2);
    }
    else if (int <= 65535) {
        return 'fd' + (await (0, encode_js_1.reverseHex)(await (0, encode_js_1.padZeroHexN)(int.toString(16), 4)));
    }
    else if (int <= 4294967295) {
        return 'fe' + (await (0, encode_js_1.reverseHex)(await (0, encode_js_1.padZeroHexN)(int.toString(16), 8)));
    }
    else {
        return 'ff' + (await (0, encode_js_1.reverseHex)(await (0, encode_js_1.padZeroHexN)(int.toString(16), 16)));
    }
};
exports.getVarInt = getVarInt;
const pushData = async (dataToRead) => {
    return dataToRead.length / 2 < 76
        ? await (0, encode_js_1.padZeroHexN)((dataToRead.length / 2).toString(16), 2)
        : dataToRead.length / 2 < 256
            ? opcode_js_1.Opcode.OP_PUSHDATA1 +
                (await (0, encode_js_1.padZeroHexN)((dataToRead.length / 2).toString(16), 2))
            : opcode_js_1.Opcode.OP_PUSHDATA2 +
                (await (0, encode_js_1.reverseHex)(await (0, encode_js_1.padZeroHexN)((dataToRead.length / 2).toString(16), 4)));
};
exports.pushData = pushData;
