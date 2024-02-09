import { padZeroHexN, reverseHex } from './encode.js';
import { Opcode } from './opcode.js';
export const getVarInt = async (int) => {
    if (int <= 252) {
        return await padZeroHexN(int.toString(16), 2);
    }
    else if (int <= 65535) {
        return 'fd' + (await reverseHex(await padZeroHexN(int.toString(16), 4)));
    }
    else if (int <= 4294967295) {
        return 'fe' + (await reverseHex(await padZeroHexN(int.toString(16), 8)));
    }
    else {
        return 'ff' + (await reverseHex(await padZeroHexN(int.toString(16), 16)));
    }
};
export const pushData = async (dataToRead) => {
    return dataToRead.length / 2 < 76
        ? await padZeroHexN((dataToRead.length / 2).toString(16), 2)
        : dataToRead.length / 2 < 256
            ? Opcode.OP_PUSHDATA1 +
                (await padZeroHexN((dataToRead.length / 2).toString(16), 2))
            : Opcode.OP_PUSHDATA2 +
                (await reverseHex(await padZeroHexN((dataToRead.length / 2).toString(16), 4)));
};
