//! Method bodies (ECMA-335 II.25.4) and the CIL instruction stream (partition III). Only the
//! instructions a call graph needs are kept; every other one is stepped over by its operand
//! width, and an opcode the standard does not define is an error, never skipped.

use crate::metadata::{u16_at, u32_at, u8_at, Image};
use crate::ClrError;

/// An instruction the call graph needs, with its raw metadata token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Raw {
    /// `call`, `callvirt`, `newobj`, `ldftn`, `ldvirtftn`, `jmp`: a method token.
    Method(Invoke, u32),
    /// `ldstr`: a `#US` heap offset.
    Str(u32),
    /// `ldtoken`: a type, method or field token.
    Token(u32),
    /// `ldsfld`, `ldsflda`, `stsfld`: a field token; the field's type is initialized.
    StaticField(u32),
    /// A type token that may bring a value type into being without `newobj`: `initobj`,
    /// `box`, `newarr`, `constrained.`, `ldobj`, `stobj`, `cpobj`, `unbox`, `unbox.any`,
    /// `ldelem`, `stelem`, `ldelema`, `sizeof`. Not an op of its own.
    Mention(u32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Invoke {
    Call,
    CallVirt,
    NewObj,
    LdFtn,
    LdVirtFtn,
    Jmp,
}

/// How many operand bytes follow an opcode, or `None` for `switch` (a count, then targets).
#[derive(Clone, Copy)]
enum Operand {
    Fixed(usize),
    Switch,
}

/// The operand of a one-byte opcode; `None` where the standard defines no instruction.
fn one_byte(op: u8) -> Option<Operand> {
    use Operand::Fixed;
    Some(match op {
        0x00..=0x0D => Fixed(0),
        0x0E..=0x13 => Fixed(1), // ldarg.s .. stloc.s
        0x14..=0x1E => Fixed(0), // ldnull, ldc.i4.m1 .. ldc.i4.8
        0x1F => Fixed(1),        // ldc.i4.s
        0x20 => Fixed(4),        // ldc.i4
        0x21 => Fixed(8),        // ldc.i8
        0x22 => Fixed(4),        // ldc.r4
        0x23 => Fixed(8),        // ldc.r8
        0x25 | 0x26 => Fixed(0), // dup, pop
        0x27..=0x29 => Fixed(4), // jmp, call, calli
        0x2A => Fixed(0),        // ret
        0x2B..=0x37 => Fixed(1), // short branches
        0x38..=0x44 => Fixed(4), // branches
        0x45 => Operand::Switch,
        0x46..=0x6E => Fixed(0), // ldind, stind, arithmetic, conv
        0x6F..=0x75 => Fixed(4), // callvirt, cpobj, ldobj, ldstr, newobj, castclass, isinst
        0x76 => Fixed(0),        // conv.r.un
        0x79 => Fixed(4),        // unbox
        0x7A => Fixed(0),        // throw
        0x7B..=0x81 => Fixed(4), // ldfld .. stobj
        0x82..=0x8B => Fixed(0), // conv.ovf.*.un
        0x8C | 0x8D => Fixed(4), // box, newarr
        0x8E => Fixed(0),        // ldlen
        0x8F => Fixed(4),        // ldelema
        0x90..=0xA2 => Fixed(0), // ldelem.*, stelem.*
        0xA3..=0xA5 => Fixed(4), // ldelem, stelem, unbox.any
        0xB3..=0xBA => Fixed(0), // conv.ovf.*
        0xC2 => Fixed(4),        // refanyval
        0xC3 => Fixed(0),        // ckfinite
        0xC6 => Fixed(4),        // mkrefany
        0xD0 => Fixed(4),        // ldtoken
        0xD1..=0xDC => Fixed(0), // conv.u2 .. endfinally
        0xDD => Fixed(4),        // leave
        0xDE => Fixed(1),        // leave.s
        0xDF | 0xE0 => Fixed(0), // stind.i, conv.u
        _ => return None,
    })
}

/// The operand of `0xFE`-prefixed opcode `op`.
fn two_byte(op: u8) -> Option<Operand> {
    use Operand::Fixed;
    Some(match op {
        0x00..=0x05 => Fixed(0), // arglist, ceq, cgt, cgt.un, clt, clt.un
        0x06 | 0x07 => Fixed(4), // ldftn, ldvirtftn
        0x09..=0x0E => Fixed(2), // ldarg .. stloc
        0x0F => Fixed(0),        // localloc
        0x11 => Fixed(0),        // endfilter
        0x12 => Fixed(1),        // unaligned.
        0x13 | 0x14 => Fixed(0), // volatile., tail.
        0x15 | 0x16 => Fixed(4), // initobj, constrained.
        0x17 | 0x18 => Fixed(0), // cpblk, initblk
        0x19 => Fixed(1),        // no.
        0x1A => Fixed(0),        // rethrow
        0x1C => Fixed(4),        // sizeof
        0x1D | 0x1E => Fixed(0), // refanytype, readonly.
        _ => return None,
    })
}

/// The code bytes of the method body at `rva`.
pub(crate) fn body<'a>(image: &Image<'a>, rva: u32) -> Result<&'a [u8], ClrError> {
    let bytes = image.bytes();
    let at = image.offset(rva)?;
    let first = u8_at(bytes, at)?;
    let (start, size) = match first & 0x3 {
        0x2 => (at + 1, usize::from(first >> 2)),
        0x3 => {
            let header = usize::from(u16_at(bytes, at)? >> 12) * 4;
            (at + header, u32_at(bytes, at + 4)? as usize)
        }
        _ => return Err(ClrError::BadBody(rva)),
    };
    bytes
        .get(start..start + size)
        .ok_or(ClrError::Truncated("method body"))
}

/// The instructions of `code` that a call graph needs, in order.
pub(crate) fn decode(code: &[u8]) -> Result<Vec<Raw>, ClrError> {
    let mut out = Vec::new();
    let mut at = 0;
    while at < code.len() {
        let op = code[at];
        let (operand, wide, next) = if op == 0xFE {
            let second = u8_at(code, at + 1)?;
            (
                two_byte(second).ok_or(ClrError::BadOpcode(0xFE00 | u16::from(second)))?,
                Some(second),
                at + 2,
            )
        } else {
            (
                one_byte(op).ok_or(ClrError::BadOpcode(u16::from(op)))?,
                None,
                at + 1,
            )
        };
        let len = match operand {
            Operand::Fixed(n) => n,
            Operand::Switch => 4 + 4 * u32_at(code, next)? as usize,
        };
        if next + len > code.len() {
            return Err(ClrError::Truncated("instruction"));
        }
        let token = || u32_at(code, next);
        let raw = match (wide, op) {
            (None, 0x27) => Some(Raw::Method(Invoke::Jmp, token()?)),
            (None, 0x28) => Some(Raw::Method(Invoke::Call, token()?)),
            (None, 0x6F) => Some(Raw::Method(Invoke::CallVirt, token()?)),
            (None, 0x73) => Some(Raw::Method(Invoke::NewObj, token()?)),
            (None, 0x72) => Some(Raw::Str(token()? & 0x00FF_FFFF)),
            (None, 0xD0) => Some(Raw::Token(token()?)),
            (None, 0x7E..=0x80) => Some(Raw::StaticField(token()?)),
            (None, 0x70 | 0x71 | 0x79 | 0x81 | 0x8C | 0x8D | 0x8F | 0xA3..=0xA5)
            | (Some(0x15 | 0x16 | 0x1C), _) => Some(Raw::Mention(token()?)),
            (Some(0x06), _) => Some(Raw::Method(Invoke::LdFtn, token()?)),
            (Some(0x07), _) => Some(Raw::Method(Invoke::LdVirtFtn, token()?)),
            _ => None,
        };
        out.extend(raw);
        at = next + len;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn steps_over_operands_and_keeps_calls() {
        // ldc.i4.s 5; switch (2) t1 t2; ldstr 0x70000001; call 0x0A000002; FE 06 ldftn
        // 0x06000003; ret
        let code = [
            0x1F, 5, 0x45, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x72, 1, 0, 0, 0x70, 0x28, 2, 0, 0,
            0x0A, 0xFE, 0x06, 3, 0, 0, 0x06, 0x2A,
        ];
        assert_eq!(
            decode(&code).unwrap(),
            [
                Raw::Str(1),
                Raw::Method(Invoke::Call, 0x0A00_0002),
                Raw::Method(Invoke::LdFtn, 0x0600_0003),
            ]
        );
    }

    #[test]
    fn an_undefined_opcode_is_an_error() {
        assert!(matches!(decode(&[0x24]), Err(ClrError::BadOpcode(0x24))));
        assert!(matches!(
            decode(&[0xFE, 0x08]),
            Err(ClrError::BadOpcode(0xFE08))
        ));
        assert!(decode(&[0x28, 1, 0]).is_err(), "a cut operand");
    }
}
