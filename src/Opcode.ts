/** Script opcodes */
enum Opcode {
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
  OP_0 = "00",
  OP_FALSE = OP_0,
  /**
   * read the next byte as N and push the next N bytes as an array onto the stack
   */
  OP_PUSHDATA1 = "4c",
  /**
   * read the next 2 bytes as N and push the next N bytes as an array onto the stack
   */
  OP_PUSHDATA2 = "4d",
  /**
   * read the next 4 bytes as N and push the next N bytes as an array onto the stack
   */
  OP_PUSHDATA4 = "4e",
  /**
   * push "\x81" onto the stack (which is interpreted as -1 by numerical opcodes)
   */
  OP_1NEGATE = "4f",
  /**
   * mark transaction invalid
   * turned into OP_SUCCESS80 in tapscript
   */
  OP_RESERVED = "50",
  /**
   * both opcodes below push "\x01" onto the stack (which is interpreted as 1 by numerical opcodes)
   */
  OP_1 = "51",
  OP_TRUE = OP_1,
  /**
   * push "\x02" onto the stack (which is interpreted as 2 by numerical opcodes)
   */
  OP_2 = "52",
  /**
   * push "\x03" onto the stack (which is interpreted as 3 by numerical opcodes)
   */
  OP_3 = "53",
  /**
   * push "\x04" onto the stack (which is interpreted as 4 by numerical opcodes)
   */
  OP_4 = "54",
  /**
   * push "\x05" onto the stack (which is interpreted as 5 by numerical opcodes)
   */
  OP_5 = "55",
  /**
   * push "\x06" onto the stack (which is interpreted as 6 by numerical opcodes)
   */
  OP_6 = "56",
  /**
   * push "\x07" onto the stack (which is interpreted as 7 by numerical opcodes)
   */
  OP_7 = "57",
  /**
   * push "\x08" onto the stack (which is interpreted as 8 by numerical opcodes)
   */
  OP_8 = "58",
  /**
   * push "\x09" onto the stack (which is interpreted as 9 by numerical opcodes)
   */
  OP_9 = "59",
  /**
   * push "\x0A" onto the stack (which is interpreted as 10 by numerical opcodes)
   */
  OP_10 = "5a",
  /**
   * push "\x0B" onto the stack (which is interpreted as 11 by numerical opcodes)
   */
  OP_11 = "5b",
  /**
   * push "\x0C" onto the stack (which is interpreted as 12 by numerical opcodes)
   */
  OP_12 = "5c",
  /**
   * push "\x0D" onto the stack (which is interpreted as 13 by numerical opcodes)
   */
  OP_13 = "5d",
  /**
   * push "\x0E" onto the stack (which is interpreted as 14 by numerical opcodes)
   */
  OP_14 = "5e",
  /**
   * push "\x0F" onto the stack (which is interpreted as 15 by numerical opcodes)
   */
  OP_15 = "5f",
  /**
   * push "\x10" onto the stack (which is interpreted as 16 by numerical opcodes)
   */
  OP_16 = "60",

  /** control */
  /**
   * do nothing
   */
  OP_NOP = "61",
  /**
   * opcode below is disabled
   * mark transaction invalid
   * turned into OP_SUCCESS98 in tapscript
   */
  OP_VER = "62",
  /**
   * if top stack value is true (exactly "\x01" for tapscript)', execute the statement
   */
  OP_IF = "63",
  /**
   * if top stack value is false ("" for tapscript)', execute the statement
   */
  OP_NOTIF = "64",
  /**
   * both opcodes below are disabled
   * mark transaction invalid even when occurring in an unexecuted branch
   */
  OP_VERIF = "65",
  OP_VERNOTIF = "66",
  /**
   * if the preceding OP_IF', OP_NOTIF or OP_ELSE not executed', execute the statement
   */
  OP_ELSE = "67",
  /**
   * end if/else block (must include', otherwise tx becomes invalid)
   */
  OP_ENDIF = "68",
  /**
   * mark transaction invalid if top stack value is false
   */
  OP_VERIFY = "69",
  /**
   * mark transaction invalid
   */
  OP_RETURN = "6a",

  /** stack ops */
  /**
   * pop an item from the main stack onto the alt stack
   */
  OP_TOALTSTACK = "6b",
  /**
   * pop an item from the alt stack onto the main stack
   */
  OP_FROMALTSTACK = "6c",
  /**
   * remove the two top stack items
   * [ ... x0 x1 ] -> [ ... ]
   */
  OP_2DROP = "6d",
  /**
   * duplicate top and second from top stack items
   * [ ... x0 x1 ] -> [ ... x0 x1 x0 x1 ]
   */
  OP_2DUP = "6e",
  /**
   * duplicate top', second from top and third from top stack items
   * [ ... x0 x1 x2 ] -> [ ... x0 x1 x2 x0 x1 x2 ]
   */
  OP_3DUP = "6f",
  /**
   * copy third and fourth from top stack items to the top
   * [ ... x0 x1 x2 x3 ] -> [ ... x0 x1 x2 x3 x0 x1 ]
   */
  OP_2OVER = "70",
  /**
   * move fifth and sixth from top stack items to the top
   * [ ... x0 x1 x2 x3 x4 x5 ] -> [ ... x2 x3 x4 x5 x0 x1 ]
   */
  OP_2ROT = "71",
  /**
   * swap: top and second from top <-> third and fourth from top items of stack
   * [ ... x0 x1 x2 x3 ] -> [ ... x2 x3 x0 x1 ]
   */
  OP_2SWAP = "72",
  /**
   * if top stack value is true', OP_DUP
   */
  OP_IFDUP = "73",
  /**
   * push the current number of stack items onto the stack
   * [ x0 x1 ... xN ] -> [ x0 x1 ... xN N+1 ]
   */
  OP_DEPTH = "74",
  /**
   * remove top stack item
   * [ ... x0 ] -> [ ... ]
   */
  OP_DROP = "75",
  /**
   * duplicate top stack item
   * [ ... x0 ] -> [ ... x0 x0 ]
   */
  OP_DUP = "76",
  /**
   * remove second from top stack item
   * [ ... x0 x1 ] -> [ ... x1 ]
   */
  OP_NIP = "77",
  /**
   * copy second from top stack item to the top
   * [ ... x0 x1 ] -> [ ... x0 x1 x0 ]
   */
  OP_OVER = "78",
  /**
   * copy item N back in stack to the top
   * [ ... x0 x1 ... xN N+1 ] -> [ ... x0 x1 ... xN x0 ]
   */
  OP_PICK = "79",
  /**
   * move item N back in stack to the top
   * [ ... x0 x1 ... xN N+1 ] -> [ ... x1 ... xN x0 ]
   */
  OP_ROLL = "7a",
  /**
   * move third from top stack item to the top
   * [ ... x0 x1 x2 ] -> [ ... x1 x2 x0 ]
   */
  OP_ROT = "7b",
  /**
   * swap top two items of stack
   * [ ... x0 x1 ] -> [ ... x1 x0]
   */
  OP_SWAP = "7c",
  /**
   * copy top stack item and insert before second from top item
   * [ ... x0 x1 ] -> [ ... x1 x0 x1 ]
   */
  OP_TUCK = "7d",

  /** splice ops */
  /**
   * opcodes below until OP_SIZE are disabled
   * mark transaction invalid even when occurring in an unexecuted branch
   * turned into OP_SUCCESS126-129 in tapscript
   */
  OP_CAT = "7e",
  OP_SUBSTR = "7f",
  OP_LEFT = "80",
  OP_RIGHT = "81",
  /**
   * push the length of top stack item (not pop the top element whose size is inspected)
   */
  OP_SIZE = "82",

  /** bit logic */
  /**
   * opcodes below until OP_EQUAL are disabled
   * mark transaction invalid even when occurring in an unexecuted branch
   * turned into OP_SUCCESS131-134 in tapscript
   */
  OP_INVERT = "83",
  OP_AND = "84",
  OP_OR = "85",
  OP_XOR = "86",
  /**
   * pop two top stack items and push "\x01" if they are equal', otherwise ""
   */
  OP_EQUAL = "87",
  /**
   * execute OP_EQUAL', then OP_VERIFY afterward
   */
  OP_EQUALVERIFY = "88",
  /**
   * both opcodes below mark transaction invalid
   * turned into OP_SUCCESS137-138 in tapscript
   */
  OP_RESERVED1 = "89",
  OP_RESERVED2 = "8a",

  /** numeric */
  /**
   * add 1 to the top stack item
   */
  OP_1ADD = "8b",
  /**
   * subtract 1 from the top stack item
   */
  OP_1SUB = "8c",
  /**
   * both opcodes below are disabled
   * mark transaction invalid even when occurring in an unexecuted branch
   * turned into OP_SUCCESS141-142 in tapscript
   */
  OP_2MUL = "8d",
  OP_2DIV = "8e",
  /**
   * multiply the top stack item by -1
   */
  OP_NEGATE = "8f",
  /**
   * replace top stack item by its absolute value
   */
  OP_ABS = "90",
  /**
   * replace top stack item by "\x01" if its value is 0', otherwise ""
   */
  OP_NOT = "91",
  /**
   * replace top stack item by "" if its value is 0', otherwise by "\x01"
   */
  OP_0NOTEQUAL = "92",

  /**
   * pop two top stack items and push their sum
   */
  OP_ADD = "93",
  /**
   * pop two top stack items and push the second minus the top
   */
  OP_SUB = "94",
  /**
   * opcodes below until OP_BOOLAND are disabled
   * mark transaction invalid even when occurring in an unexecuted branch
   * turned into OP_SUCCESS149-153 in tapscript
   */
  OP_MUL = "95",
  OP_DIV = "96",
  OP_MOD = "97",
  OP_LSHIFT = "98",
  OP_RSHIFT = "99",

  /**
   * pop two top stack items and push "\x01" if they are both true', "" otherwise
   */
  OP_BOOLAND = "9a",
  /**
   * pop two top stack items and push "\x01" if top or second from top stack item is not 0', otherwise ""
   */
  OP_BOOLOR = "9b",
  /**
   * pop two top stack items and push "\x01" if inputs are equal', otherwise ""
   */
  OP_NUMEQUAL = "9c",
  /**
   * execute OP_NUMEQUAL', then OP_VERIFY afterward
   */
  OP_NUMEQUALVERIFY = "9d",
  /**
   * pop two top stack items and push "\x01" if inputs are not equal', otherwise ""
   */
  OP_NUMNOTEQUAL = "9e",
  /**
   * pop two top stack items and push "\x01" if second from top < top', otherwise ""
   */
  OP_LESSTHAN = "9f",
  /**
   * pop two top stack items and push "\x01" if second from top > top', otherwise ""
   */
  OP_GREATERTHAN = "a0",
  /**
   * pop two top stack items and push "\x01" if second from top <= top', otherwise ""
   */
  OP_LESSTHANOREQUAL = "a1",
  /**
   * pop two top stack items and push "\x01" if second from top >= top', otherwise ""
   */
  OP_GREATERTHANOREQUAL = "a2",
  /**
   * pop two top stack items and push the smaller
   */
  OP_MIN = "a3",
  /**
   * pop two top stack items and push the bigger
   */
  OP_MAX = "a4",

  /**
   * pop three top stack items and push "\x01" if third from top > top >= second from top', otherwise ""
   */
  OP_WITHIN = "a5",

  /** crypto */
  /**
   * replace top stack item by its RIPEMD-160 hash
   */
  OP_RIPEMD160 = "a6",
  /**
   * replace top stack item by its SHA-1 hash
   */
  OP_SHA1 = "a7",
  /**
   * replace top stack item by its SHA-256 hash
   */
  OP_SHA256 = "a8",
  /**
   * replace top stack item by hashing SHA-256 then RIPEMD-160
   */
  OP_HASH160 = "a9",
  /**
   * replace top stack item by hashing SHA-256 twice
   */
  OP_HASH256 = "aa",
  /**
   * all of the signature checking words will only match signatures to the data
   * after the most recently-executed OP_CODESEPARATOR
   */
  OP_CODESEPARATOR = "ab",
  /**
   * push "\x01" if signature is valid for tx hash and public key', otherwise ""
   */
  OP_CHECKSIG = "ac",
  /**
   * execute OP_CHECKSIG', then OP_VERIFY afterward
   */
  OP_CHECKSIGVERIFY = "ad",
  /**
   * OP_CHECKSIG for multiple signatures
   */
  OP_CHECKMULTISIG = "ae",
  /**
   * execute OP_CHECKMULTISIG', then OP_VERIFY afterward
   */
  OP_CHECKMULTISIGVERIFY = "af",

  /** expansion */
  /**
   * do nothing
   */
  OP_NOP1 = "b0",
  /**
   * both below are absolute lock time (check details in BIP65)
   */
  OP_CHECKLOCKTIMEVERIFY = "b1",
  OP_NOP2 = OP_CHECKLOCKTIMEVERIFY,
  /**
   * both below are relative lock time (check details in BIP68 and BIP112)
   */
  OP_CHECKSEQUENCEVERIFY = "b2",
  OP_NOP3 = OP_CHECKSEQUENCEVERIFY,
  /**
   * opcodes below do nothing
   */
  OP_NOP4 = "b3",
  OP_NOP5 = "b4",
  OP_NOP6 = "b5",
  OP_NOP7 = "b6",
  OP_NOP8 = "b7",
  OP_NOP9 = "b8",
  OP_NOP10 = "b9",

  /**
   * Opcode added by BIP 342 (Tapscript)
   * pop the public key', N and a signature', push N if signature is empty',
   * fail if it's invalid', otherwise push N + 1 (see BIP 342)
   */
  OP_CHECKSIGADD = "ba",

  OP_INVALIDOPCODE = "ff",
}

export default Opcode;
