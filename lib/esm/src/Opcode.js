/** Script opcodes */
export var Opcode;
(function (Opcode) {
    /**
     * Opcodes that take a true/false value will evaluate the following as false:
     *     an empty vector
     *     a vector (of any length) of all zero bytes
     *     a single byte of "\x80" ('negative zero')
     *     a vector (of any length) of all zero bytes except the last byte is "\x80"
     *
     * Any other value will evaluate to true.
     *
     * Unless specified otherwise', all opcodes below only have an effect when they occur in executed branches.
     */
    /** push value */
    /**
     * both opcodes below push "" onto the stack (which is an empty array of bytes)
     */
    Opcode["OP_0"] = "00";
    Opcode["OP_FALSE"] = "00";
    /**
     * read the next byte as N and push the next N bytes as an array onto the stack
     */
    Opcode["OP_PUSHDATA1"] = "4c";
    /**
     * read the next 2 bytes as N and push the next N bytes as an array onto the stack
     */
    Opcode["OP_PUSHDATA2"] = "4d";
    /**
     * read the next 4 bytes as N and push the next N bytes as an array onto the stack
     */
    Opcode["OP_PUSHDATA4"] = "4e";
    /**
     * push "\x81" onto the stack (which is interpreted as -1 by numerical opcodes)
     */
    Opcode["OP_1NEGATE"] = "4f";
    /**
     * mark transaction invalid
     * turned into OP_SUCCESS80 in tapscript
     */
    Opcode["OP_RESERVED"] = "50";
    /**
     * both opcodes below push "\x01" onto the stack (which is interpreted as 1 by numerical opcodes)
     */
    Opcode["OP_1"] = "51";
    Opcode["OP_TRUE"] = "51";
    /**
     * push "\x02" onto the stack (which is interpreted as 2 by numerical opcodes)
     */
    Opcode["OP_2"] = "52";
    /**
     * push "\x03" onto the stack (which is interpreted as 3 by numerical opcodes)
     */
    Opcode["OP_3"] = "53";
    /**
     * push "\x04" onto the stack (which is interpreted as 4 by numerical opcodes)
     */
    Opcode["OP_4"] = "54";
    /**
     * push "\x05" onto the stack (which is interpreted as 5 by numerical opcodes)
     */
    Opcode["OP_5"] = "55";
    /**
     * push "\x06" onto the stack (which is interpreted as 6 by numerical opcodes)
     */
    Opcode["OP_6"] = "56";
    /**
     * push "\x07" onto the stack (which is interpreted as 7 by numerical opcodes)
     */
    Opcode["OP_7"] = "57";
    /**
     * push "\x08" onto the stack (which is interpreted as 8 by numerical opcodes)
     */
    Opcode["OP_8"] = "58";
    /**
     * push "\x09" onto the stack (which is interpreted as 9 by numerical opcodes)
     */
    Opcode["OP_9"] = "59";
    /**
     * push "\x0A" onto the stack (which is interpreted as 10 by numerical opcodes)
     */
    Opcode["OP_10"] = "5a";
    /**
     * push "\x0B" onto the stack (which is interpreted as 11 by numerical opcodes)
     */
    Opcode["OP_11"] = "5b";
    /**
     * push "\x0C" onto the stack (which is interpreted as 12 by numerical opcodes)
     */
    Opcode["OP_12"] = "5c";
    /**
     * push "\x0D" onto the stack (which is interpreted as 13 by numerical opcodes)
     */
    Opcode["OP_13"] = "5d";
    /**
     * push "\x0E" onto the stack (which is interpreted as 14 by numerical opcodes)
     */
    Opcode["OP_14"] = "5e";
    /**
     * push "\x0F" onto the stack (which is interpreted as 15 by numerical opcodes)
     */
    Opcode["OP_15"] = "5f";
    /**
     * push "\x10" onto the stack (which is interpreted as 16 by numerical opcodes)
     */
    Opcode["OP_16"] = "60";
    /** control */
    /**
     * do nothing
     */
    Opcode["OP_NOP"] = "61";
    /**
     * opcode below is disabled
     * mark transaction invalid
     * turned into OP_SUCCESS98 in tapscript
     */
    Opcode["OP_VER"] = "62";
    /**
     * if top stack value is true (exactly "\x01" for tapscript)', execute the statement
     */
    Opcode["OP_IF"] = "63";
    /**
     * if top stack value is false ("" for tapscript)', execute the statement
     */
    Opcode["OP_NOTIF"] = "64";
    /**
     * both opcodes below are disabled
     * mark transaction invalid even when occurring in an unexecuted branch
     */
    Opcode["OP_VERIF"] = "65";
    Opcode["OP_VERNOTIF"] = "66";
    /**
     * if the preceding OP_IF', OP_NOTIF or OP_ELSE not executed', execute the statement
     */
    Opcode["OP_ELSE"] = "67";
    /**
     * end if/else block (must include', otherwise tx becomes invalid)
     */
    Opcode["OP_ENDIF"] = "68";
    /**
     * mark transaction invalid if top stack value is false
     */
    Opcode["OP_VERIFY"] = "69";
    /**
     * mark transaction invalid
     */
    Opcode["OP_RETURN"] = "6a";
    /** stack ops */
    /**
     * pop an item from the main stack onto the alt stack
     */
    Opcode["OP_TOALTSTACK"] = "6b";
    /**
     * pop an item from the alt stack onto the main stack
     */
    Opcode["OP_FROMALTSTACK"] = "6c";
    /**
     * remove the two top stack items
     * [ ... x0 x1 ] -> [ ... ]
     */
    Opcode["OP_2DROP"] = "6d";
    /**
     * duplicate top and second from top stack items
     * [ ... x0 x1 ] -> [ ... x0 x1 x0 x1 ]
     */
    Opcode["OP_2DUP"] = "6e";
    /**
     * duplicate top', second from top and third from top stack items
     * [ ... x0 x1 x2 ] -> [ ... x0 x1 x2 x0 x1 x2 ]
     */
    Opcode["OP_3DUP"] = "6f";
    /**
     * copy third and fourth from top stack items to the top
     * [ ... x0 x1 x2 x3 ] -> [ ... x0 x1 x2 x3 x0 x1 ]
     */
    Opcode["OP_2OVER"] = "70";
    /**
     * move fifth and sixth from top stack items to the top
     * [ ... x0 x1 x2 x3 x4 x5 ] -> [ ... x2 x3 x4 x5 x0 x1 ]
     */
    Opcode["OP_2ROT"] = "71";
    /**
     * swap: top and second from top <-> third and fourth from top items of stack
     * [ ... x0 x1 x2 x3 ] -> [ ... x2 x3 x0 x1 ]
     */
    Opcode["OP_2SWAP"] = "72";
    /**
     * if top stack value is true', OP_DUP
     */
    Opcode["OP_IFDUP"] = "73";
    /**
     * push the current number of stack items onto the stack
     * [ x0 x1 ... xN ] -> [ x0 x1 ... xN N+1 ]
     */
    Opcode["OP_DEPTH"] = "74";
    /**
     * remove top stack item
     * [ ... x0 ] -> [ ... ]
     */
    Opcode["OP_DROP"] = "75";
    /**
     * duplicate top stack item
     * [ ... x0 ] -> [ ... x0 x0 ]
     */
    Opcode["OP_DUP"] = "76";
    /**
     * remove second from top stack item
     * [ ... x0 x1 ] -> [ ... x1 ]
     */
    Opcode["OP_NIP"] = "77";
    /**
     * copy second from top stack item to the top
     * [ ... x0 x1 ] -> [ ... x0 x1 x0 ]
     */
    Opcode["OP_OVER"] = "78";
    /**
     * copy item N back in stack to the top
     * [ ... x0 x1 ... xN N+1 ] -> [ ... x0 x1 ... xN x0 ]
     */
    Opcode["OP_PICK"] = "79";
    /**
     * move item N back in stack to the top
     * [ ... x0 x1 ... xN N+1 ] -> [ ... x1 ... xN x0 ]
     */
    Opcode["OP_ROLL"] = "7a";
    /**
     * move third from top stack item to the top
     * [ ... x0 x1 x2 ] -> [ ... x1 x2 x0 ]
     */
    Opcode["OP_ROT"] = "7b";
    /**
     * swap top two items of stack
     * [ ... x0 x1 ] -> [ ... x1 x0]
     */
    Opcode["OP_SWAP"] = "7c";
    /**
     * copy top stack item and insert before second from top item
     * [ ... x0 x1 ] -> [ ... x1 x0 x1 ]
     */
    Opcode["OP_TUCK"] = "7d";
    /** splice ops */
    /**
     * opcodes below until OP_SIZE are disabled
     * mark transaction invalid even when occurring in an unexecuted branch
     * turned into OP_SUCCESS126-129 in tapscript
     */
    Opcode["OP_CAT"] = "7e";
    Opcode["OP_SUBSTR"] = "7f";
    Opcode["OP_LEFT"] = "80";
    Opcode["OP_RIGHT"] = "81";
    /**
     * push the length of top stack item (not pop the top element whose size is inspected)
     */
    Opcode["OP_SIZE"] = "82";
    /** bit logic */
    /**
     * opcodes below until OP_EQUAL are disabled
     * mark transaction invalid even when occurring in an unexecuted branch
     * turned into OP_SUCCESS131-134 in tapscript
     */
    Opcode["OP_INVERT"] = "83";
    Opcode["OP_AND"] = "84";
    Opcode["OP_OR"] = "85";
    Opcode["OP_XOR"] = "86";
    /**
     * pop two top stack items and push "\x01" if they are equal', otherwise ""
     */
    Opcode["OP_EQUAL"] = "87";
    /**
     * execute OP_EQUAL', then OP_VERIFY afterward
     */
    Opcode["OP_EQUALVERIFY"] = "88";
    /**
     * both opcodes below mark transaction invalid
     * turned into OP_SUCCESS137-138 in tapscript
     */
    Opcode["OP_RESERVED1"] = "89";
    Opcode["OP_RESERVED2"] = "8a";
    /** numeric */
    /**
     * add 1 to the top stack item
     */
    Opcode["OP_1ADD"] = "8b";
    /**
     * subtract 1 from the top stack item
     */
    Opcode["OP_1SUB"] = "8c";
    /**
     * both opcodes below are disabled
     * mark transaction invalid even when occurring in an unexecuted branch
     * turned into OP_SUCCESS141-142 in tapscript
     */
    Opcode["OP_2MUL"] = "8d";
    Opcode["OP_2DIV"] = "8e";
    /**
     * multiply the top stack item by -1
     */
    Opcode["OP_NEGATE"] = "8f";
    /**
     * replace top stack item by its absolute value
     */
    Opcode["OP_ABS"] = "90";
    /**
     * replace top stack item by "\x01" if its value is 0', otherwise ""
     */
    Opcode["OP_NOT"] = "91";
    /**
     * replace top stack item by "" if its value is 0', otherwise by "\x01"
     */
    Opcode["OP_0NOTEQUAL"] = "92";
    /**
     * pop two top stack items and push their sum
     */
    Opcode["OP_ADD"] = "93";
    /**
     * pop two top stack items and push the second minus the top
     */
    Opcode["OP_SUB"] = "94";
    /**
     * opcodes below until OP_BOOLAND are disabled
     * mark transaction invalid even when occurring in an unexecuted branch
     * turned into OP_SUCCESS149-153 in tapscript
     */
    Opcode["OP_MUL"] = "95";
    Opcode["OP_DIV"] = "96";
    Opcode["OP_MOD"] = "97";
    Opcode["OP_LSHIFT"] = "98";
    Opcode["OP_RSHIFT"] = "99";
    /**
     * pop two top stack items and push "\x01" if they are both true', "" otherwise
     */
    Opcode["OP_BOOLAND"] = "9a";
    /**
     * pop two top stack items and push "\x01" if top or second from top stack item is not 0', otherwise ""
     */
    Opcode["OP_BOOLOR"] = "9b";
    /**
     * pop two top stack items and push "\x01" if inputs are equal', otherwise ""
     */
    Opcode["OP_NUMEQUAL"] = "9c";
    /**
     * execute OP_NUMEQUAL', then OP_VERIFY afterward
     */
    Opcode["OP_NUMEQUALVERIFY"] = "9d";
    /**
     * pop two top stack items and push "\x01" if inputs are not equal', otherwise ""
     */
    Opcode["OP_NUMNOTEQUAL"] = "9e";
    /**
     * pop two top stack items and push "\x01" if second from top < top', otherwise ""
     */
    Opcode["OP_LESSTHAN"] = "9f";
    /**
     * pop two top stack items and push "\x01" if second from top > top', otherwise ""
     */
    Opcode["OP_GREATERTHAN"] = "a0";
    /**
     * pop two top stack items and push "\x01" if second from top <= top', otherwise ""
     */
    Opcode["OP_LESSTHANOREQUAL"] = "a1";
    /**
     * pop two top stack items and push "\x01" if second from top >= top', otherwise ""
     */
    Opcode["OP_GREATERTHANOREQUAL"] = "a2";
    /**
     * pop two top stack items and push the smaller
     */
    Opcode["OP_MIN"] = "a3";
    /**
     * pop two top stack items and push the bigger
     */
    Opcode["OP_MAX"] = "a4";
    /**
     * pop three top stack items and push "\x01" if third from top > top >= second from top', otherwise ""
     */
    Opcode["OP_WITHIN"] = "a5";
    /** crypto */
    /**
     * replace top stack item by its RIPEMD-160 hash
     */
    Opcode["OP_RIPEMD160"] = "a6";
    /**
     * replace top stack item by its SHA-1 hash
     */
    Opcode["OP_SHA1"] = "a7";
    /**
     * replace top stack item by its SHA-256 hash
     */
    Opcode["OP_SHA256"] = "a8";
    /**
     * replace top stack item by hashing SHA-256 then RIPEMD-160
     */
    Opcode["OP_HASH160"] = "a9";
    /**
     * replace top stack item by hashing SHA-256 twice
     */
    Opcode["OP_HASH256"] = "aa";
    /**
     * all of the signature checking words will only match signatures to the data
     * after the most recently-executed OP_CODESEPARATOR
     */
    Opcode["OP_CODESEPARATOR"] = "ab";
    /**
     * push "\x01" if signature is valid for tx hash and public key', otherwise ""
     */
    Opcode["OP_CHECKSIG"] = "ac";
    /**
     * execute OP_CHECKSIG', then OP_VERIFY afterward
     */
    Opcode["OP_CHECKSIGVERIFY"] = "ad";
    /**
     * OP_CHECKSIG for multiple signatures
     */
    Opcode["OP_CHECKMULTISIG"] = "ae";
    /**
     * execute OP_CHECKMULTISIG', then OP_VERIFY afterward
     */
    Opcode["OP_CHECKMULTISIGVERIFY"] = "af";
    /** expansion */
    /**
     * do nothing
     */
    Opcode["OP_NOP1"] = "b0";
    /**
     * both below are absolute lock time (check details in BIP65)
     */
    Opcode["OP_CHECKLOCKTIMEVERIFY"] = "b1";
    Opcode["OP_NOP2"] = "b1";
    /**
     * both below are relative lock time (check details in BIP68 and BIP112)
     */
    Opcode["OP_CHECKSEQUENCEVERIFY"] = "b2";
    Opcode["OP_NOP3"] = "b2";
    /**
     * opcodes below do nothing
     */
    Opcode["OP_NOP4"] = "b3";
    Opcode["OP_NOP5"] = "b4";
    Opcode["OP_NOP6"] = "b5";
    Opcode["OP_NOP7"] = "b6";
    Opcode["OP_NOP8"] = "b7";
    Opcode["OP_NOP9"] = "b8";
    Opcode["OP_NOP10"] = "b9";
    /**
     * Opcode added by BIP 342 (Tapscript)
     * pop the public key', N and a signature', push N if signature is empty',
     * fail if it's invalid', otherwise push N + 1 (see BIP 342)
     */
    Opcode["OP_CHECKSIGADD"] = "ba";
    Opcode["OP_INVALIDOPCODE"] = "ff";
})(Opcode || (Opcode = {}));
