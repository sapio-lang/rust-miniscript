// SPDX-License-Identifier: CC0-1.0

//! Lexer
//!
//! Translates a script into a reversed sequence of tokens
//!

use core::fmt;

use bitcoin::blockdata::{opcodes, script};
use bitcoin::hex::DisplayHex as _;

use crate::prelude::*;

/// Atom of a tokenized version of a script
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[allow(missing_docs)]
pub enum Token {
    Inscription(crate::sync::Arc<bitcoin::ScriptBuf>),
    BoolAnd,
    BoolOr,
    Add,
    Equal,
    NumEqual,
    CheckSig,
    CheckSigAdd,
    CheckMultiSig,
    CheckSequenceVerify,
    CheckLockTimeVerify,
    CheckTemplateVerify,
    FromAltStack,
    ToAltStack,
    Drop,
    Dup,
    If,
    IfDup,
    NotIf,
    Else,
    EndIf,
    ZeroNotEqual,
    Size,
    Swap,
    Verify,
    Ripemd160,
    Hash160,
    Sha256,
    Hash256,
    Num(u32),
    Hash20([u8; 20]),
    Bytes32([u8; 32]),
    Bytes33([u8; 33]),
    Bytes65([u8; 65]),
}

impl fmt::Display for Token {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Token::Num(n) => write!(f, "#{}", n),
            Token::Hash20(b) => write!(f, "{}", b.as_hex()),
            Token::Bytes32(b) => write!(f, "{}", b.as_hex()),
            Token::Bytes33(b) => write!(f, "{}", b.as_hex()),
            Token::Bytes65(b) => write!(f, "{}", b.as_hex()),
            x => write!(f, "{:?}", x),
        }
    }
}

#[derive(Debug, Clone)]
/// Iterator that goes through a vector of tokens backward (our parser wants to read
/// backward and this is more efficient anyway since we can use `Vec::pop()`).
pub struct TokenIter(Vec<Token>);

impl TokenIter {
    /// Create a new TokenIter
    pub fn new(v: Vec<Token>) -> TokenIter { TokenIter(v) }

    /// Look at the top at Iterator
    pub fn peek(&self) -> Option<&Token> { self.0.last() }

    /// Push a value to the iterator
    /// This will be first value consumed by popun_
    pub fn un_next(&mut self, tok: Token) { self.0.push(tok) }

    /// The len of the iterator
    pub fn len(&self) -> usize { self.0.len() }

    /// Returns true if iterator is empty.
    pub fn is_empty(&self) -> bool { self.0.is_empty() }
}

impl Iterator for TokenIter {
    type Item = Token;

    fn next(&mut self) -> Option<Token> { self.0.pop() }
}

// The instruction iterator has already validated the encoded length.
fn instruction_size(opcode: u8, instruction: &script::Instruction) -> usize {
    match instruction {
        script::Instruction::Op(_) => 1,
        script::Instruction::PushBytes(bytes) => {
            bytes.len()
                + match opcode {
                    0x4c => 2,
                    0x4d => 3,
                    0x4e => 5,
                    _ => 1,
                }
        }
    }
}

/// Tokenize a script
pub fn lex(script: &'_ script::Script) -> Result<Vec<Token>, Error> {
    let mut ret = Vec::with_capacity(script.len());

    let mut it = script.instructions();
    let mut position = 0;
    while let Some(ins) = it.next() {
        let instruction = ins.map_err(Error::Script)?;
        let start = position;
        let opcode = script.as_bytes()[start];
        position += instruction_size(opcode, &instruction);
        if let script::Instruction::PushBytes(bytes) = instruction {
            let bytes = bytes.as_bytes();
            if (opcode == 0x4c && bytes.len() < 76)
                || (opcode == 0x4d && bytes.len() < 0x100)
                || (opcode == 0x4e && bytes.len() < 0x10000)
                || (bytes.len() == 1 && (bytes[0] == 0x81 || (1..=16).contains(&bytes[0])))
            {
                return Err(Error::Script(script::Error::NonMinimalPush));
            }
        }
        match instruction {
            script::Instruction::Op(opcodes::all::OP_BOOLAND) => {
                ret.push(Token::BoolAnd);
            }
            script::Instruction::Op(opcodes::all::OP_BOOLOR) => {
                ret.push(Token::BoolOr);
            }
            script::Instruction::Op(opcodes::all::OP_EQUAL) => {
                ret.push(Token::Equal);
            }
            script::Instruction::Op(opcodes::all::OP_EQUALVERIFY) => {
                ret.push(Token::Equal);
                ret.push(Token::Verify);
            }
            script::Instruction::Op(opcodes::all::OP_NUMEQUAL) => {
                ret.push(Token::NumEqual);
            }
            script::Instruction::Op(opcodes::all::OP_NUMEQUALVERIFY) => {
                ret.push(Token::NumEqual);
                ret.push(Token::Verify);
            }
            script::Instruction::Op(opcodes::all::OP_CHECKSIG) => {
                ret.push(Token::CheckSig);
            }
            script::Instruction::Op(opcodes::all::OP_CHECKSIGVERIFY) => {
                ret.push(Token::CheckSig);
                ret.push(Token::Verify);
            }
            // Change once the opcode name is updated
            script::Instruction::Op(opcodes::all::OP_CHECKSIGADD) => {
                ret.push(Token::CheckSigAdd);
            }
            script::Instruction::Op(opcodes::all::OP_CHECKMULTISIG) => {
                ret.push(Token::CheckMultiSig);
            }
            script::Instruction::Op(opcodes::all::OP_CHECKMULTISIGVERIFY) => {
                ret.push(Token::CheckMultiSig);
                ret.push(Token::Verify);
            }
            script::Instruction::Op(opcodes::all::OP_CSV) => {
                ret.push(Token::CheckSequenceVerify);
            }
            script::Instruction::Op(opcodes::all::OP_NOP4) => {
                ret.push(Token::CheckTemplateVerify);
            }
            script::Instruction::Op(opcodes::all::OP_CLTV) => {
                ret.push(Token::CheckLockTimeVerify);
            }
            script::Instruction::Op(opcodes::all::OP_FROMALTSTACK) => {
                ret.push(Token::FromAltStack);
            }
            script::Instruction::Op(opcodes::all::OP_TOALTSTACK) => {
                ret.push(Token::ToAltStack);
            }
            script::Instruction::Op(opcodes::all::OP_DROP) => {
                ret.push(Token::Drop);
            }
            script::Instruction::Op(opcodes::all::OP_DUP) => {
                ret.push(Token::Dup);
            }
            script::Instruction::Op(opcodes::all::OP_ADD) => {
                ret.push(Token::Add);
            }
            script::Instruction::Op(opcodes::all::OP_IF) => {
                if ret.last() == Some(&Token::Num(0)) {
                    ret.pop();
                    let protocol = it
                        .next()
                        .ok_or_else(|| Error::Inscription("missing protocol".into()))?
                        .map_err(Error::Script)?;
                    position += instruction_size(script.as_bytes()[position], &protocol);
                    if protocol
                        != script::Instruction::PushBytes(crate::ord::push_bytes(
                            crate::ord::PROTOCOL_ID,
                        ))
                    {
                        return Err(Error::Inscription("unknown protocol".into()));
                    }
                    loop {
                        let item = it
                            .next()
                            .ok_or_else(|| Error::Inscription("missing ENDIF".into()))?
                            .map_err(Error::Script)?;
                        position += instruction_size(script.as_bytes()[position], &item);
                        match item {
                            script::Instruction::Op(opcodes::all::OP_ENDIF) => break,
                            script::Instruction::PushBytes(_) => {}
                            script::Instruction::Op(op)
                                if matches!(
                                    op.classify(opcodes::ClassifyContext::TapScript),
                                    opcodes::Class::PushNum(_)
                                ) => {}
                            _ => {
                                return Err(Error::Inscription("envelope must be push-only".into()))
                            }
                        }
                    }
                    ret.push(Token::Inscription(crate::sync::Arc::new(
                        bitcoin::ScriptBuf::from_bytes(
                            script.as_bytes()[start - 1..position].to_vec(),
                        ),
                    )));
                } else {
                    ret.push(Token::If);
                }
            }
            script::Instruction::Op(opcodes::all::OP_IFDUP) => {
                ret.push(Token::IfDup);
            }
            script::Instruction::Op(opcodes::all::OP_NOTIF) => {
                ret.push(Token::NotIf);
            }
            script::Instruction::Op(opcodes::all::OP_ELSE) => {
                ret.push(Token::Else);
            }
            script::Instruction::Op(opcodes::all::OP_ENDIF) => {
                ret.push(Token::EndIf);
            }
            script::Instruction::Op(opcodes::all::OP_0NOTEQUAL) => {
                ret.push(Token::ZeroNotEqual);
            }
            script::Instruction::Op(opcodes::all::OP_SIZE) => {
                ret.push(Token::Size);
            }
            script::Instruction::Op(opcodes::all::OP_SWAP) => {
                ret.push(Token::Swap);
            }
            script::Instruction::Op(opcodes::all::OP_VERIFY) => {
                match ret.last() {
                    Some(op @ &Token::Equal)
                    | Some(op @ &Token::CheckSig)
                    | Some(op @ &Token::CheckMultiSig) => {
                        return Err(Error::NonMinimalVerify(op.clone()));
                    }
                    _ => {}
                }
                ret.push(Token::Verify);
            }
            script::Instruction::Op(opcodes::all::OP_RIPEMD160) => {
                ret.push(Token::Ripemd160);
            }
            script::Instruction::Op(opcodes::all::OP_HASH160) => {
                ret.push(Token::Hash160);
            }
            script::Instruction::Op(opcodes::all::OP_SHA256) => {
                ret.push(Token::Sha256);
            }
            script::Instruction::Op(opcodes::all::OP_HASH256) => {
                ret.push(Token::Hash256);
            }
            script::Instruction::PushBytes(bytes) => {
                if let Ok(bytes) = bytes.as_bytes().try_into() {
                    ret.push(Token::Hash20(bytes));
                } else if let Ok(bytes) = bytes.as_bytes().try_into() {
                    ret.push(Token::Bytes32(bytes));
                } else if let Ok(bytes) = bytes.as_bytes().try_into() {
                    ret.push(Token::Bytes33(bytes));
                } else if let Ok(bytes) = bytes.as_bytes().try_into() {
                    ret.push(Token::Bytes65(bytes));
                } else {
                    // check minimality of the number
                    match script::read_scriptint(bytes.as_bytes()) {
                        Ok(v) if v >= 0 => {
                            ret.push(Token::Num(v as u32));
                        }
                        Ok(n) => return Err(Error::NegativeInt { bytes: bytes.to_owned(), n }),
                        Err(err) => return Err(Error::InvalidInt { bytes: bytes.to_owned(), err }),
                    }
                }
            }
            script::Instruction::Op(opcodes::all::OP_PUSHBYTES_0) => {
                ret.push(Token::Num(0));
            }
            script::Instruction::Op(opcodes::all::OP_PUSHNUM_1) => {
                ret.push(Token::Num(1));
            }
            script::Instruction::Op(opcodes::all::OP_PUSHNUM_2) => {
                ret.push(Token::Num(2));
            }
            script::Instruction::Op(opcodes::all::OP_PUSHNUM_3) => {
                ret.push(Token::Num(3));
            }
            script::Instruction::Op(opcodes::all::OP_PUSHNUM_4) => {
                ret.push(Token::Num(4));
            }
            script::Instruction::Op(opcodes::all::OP_PUSHNUM_5) => {
                ret.push(Token::Num(5));
            }
            script::Instruction::Op(opcodes::all::OP_PUSHNUM_6) => {
                ret.push(Token::Num(6));
            }
            script::Instruction::Op(opcodes::all::OP_PUSHNUM_7) => {
                ret.push(Token::Num(7));
            }
            script::Instruction::Op(opcodes::all::OP_PUSHNUM_8) => {
                ret.push(Token::Num(8));
            }
            script::Instruction::Op(opcodes::all::OP_PUSHNUM_9) => {
                ret.push(Token::Num(9));
            }
            script::Instruction::Op(opcodes::all::OP_PUSHNUM_10) => {
                ret.push(Token::Num(10));
            }
            script::Instruction::Op(opcodes::all::OP_PUSHNUM_11) => {
                ret.push(Token::Num(11));
            }
            script::Instruction::Op(opcodes::all::OP_PUSHNUM_12) => {
                ret.push(Token::Num(12));
            }
            script::Instruction::Op(opcodes::all::OP_PUSHNUM_13) => {
                ret.push(Token::Num(13));
            }
            script::Instruction::Op(opcodes::all::OP_PUSHNUM_14) => {
                ret.push(Token::Num(14));
            }
            script::Instruction::Op(opcodes::all::OP_PUSHNUM_15) => {
                ret.push(Token::Num(15));
            }
            script::Instruction::Op(opcodes::all::OP_PUSHNUM_16) => {
                ret.push(Token::Num(16));
            }
            script::Instruction::Op(op) => return Err(Error::InvalidOpcode(op)),
        };
    }
    Ok(ret)
}

/// Lexer error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// An inscription envelope is incomplete or not push-only.
    Inscription(String),
    /// Parsed a negative number.
    InvalidInt {
        /// The bytes of the push that were attempted to be parsed.
        bytes: bitcoin::script::PushBytesBuf,
        /// The error that occurred.
        err: bitcoin::script::Error,
    },
    /// Parsed an opcode outside of the Miniscript language.
    InvalidOpcode(bitcoin::Opcode),
    /// Parsed a negative number.
    NegativeInt {
        /// The bytes of the push that were parsed to a negative number.
        bytes: bitcoin::script::PushBytesBuf,
        /// The resulting number.
        n: i64,
    },
    /// Non-minimal verify (e.g. `CHECKSIG VERIFY` in place of `CHECKSIGVERIFY`).
    NonMinimalVerify(Token),
    /// Error iterating through script.
    Script(bitcoin::script::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Inscription(ref e) => write!(f, "invalid inscription: {}", e),
            Self::Script(ref e) => e.fmt(f),
            Self::InvalidInt { ref bytes, ref err } => write!(f, "push {} of length {} is not a key, hash or minimal integer: {}", bytes.as_bytes().as_hex(), bytes.len(), err),
            Self::InvalidOpcode(ref op) => write!(f, "found opcode {} which does not occur in Miniscript", op),
            Self::NegativeInt { ref bytes, n } => write!(f, "push {} of length {} parses as a negative number {} which does not occur in Miniscript", bytes.as_bytes().as_hex(), bytes.len(), n),
            Self::NonMinimalVerify(ref op) => write!(f, "found {} VERIFY (should be one opcode, {}VERIFY)", op, op),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {
    fn cause(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match *self {
            Self::InvalidInt { ref err, .. } => Some(err),
            Self::InvalidOpcode(..) | Self::Inscription(..) => None,
            Self::NegativeInt { .. } => None,
            Self::NonMinimalVerify(..) => None,
            Self::Script(ref e) => Some(e),
        }
    }
}
