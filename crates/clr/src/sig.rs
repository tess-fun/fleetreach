//! Signature blobs (ECMA-335 II.23.2): the classes and value types a type signature names,
//! generic arguments included, for the call graph's "this type may be made here" rule.

use crate::metadata::{compressed, table};
use crate::ClrError;

/// How deep nested signatures may go (a damaged file may loop through TypeSpecs).
const DEPTH: usize = 32;

/// A cursor over one blob, collecting every TypeDef, TypeRef or TypeSpec it names.
pub(crate) struct Sig<'b> {
    b: &'b [u8],
    at: usize,
}

/// A type the signature names, as a table and row.
pub(crate) type Named = (usize, u32);

impl<'b> Sig<'b> {
    pub(crate) fn new(b: &'b [u8]) -> Self {
        Sig { b, at: 0 }
    }

    fn byte(&mut self) -> Result<u8, ClrError> {
        let v = *self
            .b
            .get(self.at)
            .ok_or(ClrError::Truncated("signature"))?;
        self.at += 1;
        Ok(v)
    }

    fn peek(&self) -> Option<u8> {
        self.b.get(self.at).copied()
    }

    fn number(&mut self) -> Result<u32, ClrError> {
        let (v, used) = compressed(self.b.get(self.at..).unwrap_or_default())?;
        self.at += used;
        Ok(v)
    }

    fn type_def_or_ref(&mut self, out: &mut Vec<Named>) -> Result<(), ClrError> {
        let encoded = self.number()?;
        let row = encoded >> 2;
        let t = match encoded & 0x3 {
            0 => table::TYPE_DEF,
            1 => table::TYPE_REF,
            2 => table::TYPE_SPEC,
            _ => return Err(ClrError::BadCodedIndex(encoded)),
        };
        if row != 0 {
            out.push((t, row));
        }
        Ok(())
    }

    fn custom_mods(&mut self, out: &mut Vec<Named>) -> Result<(), ClrError> {
        while matches!(self.peek(), Some(0x1F | 0x20)) {
            self.at += 1;
            self.type_def_or_ref(out)?;
        }
        Ok(())
    }

    /// One `Type` (II.23.2.12), pushing what it names.
    pub(crate) fn ty(&mut self, out: &mut Vec<Named>, depth: usize) -> Result<(), ClrError> {
        if depth > DEPTH {
            return Err(ClrError::Truncated("signature nesting"));
        }
        self.custom_mods(out)?;
        match self.byte()? {
            // Primitives, string, object, typedbyref, native ints.
            0x01..=0x0E | 0x16 | 0x18 | 0x19 | 0x1C => Ok(()),
            // VALUETYPE, CLASS.
            0x11 | 0x12 => self.type_def_or_ref(out),
            // PTR, BYREF, SZARRAY, PINNED.
            0x0F | 0x10 | 0x1D | 0x45 => self.ty(out, depth + 1),
            // VAR, MVAR.
            0x13 | 0x1E => self.number().map(|_| ()),
            // ARRAY: element, rank, sizes, lower bounds.
            0x14 => {
                self.ty(out, depth + 1)?;
                self.number()?;
                for _ in 0..2 {
                    let n = self.number()?;
                    for _ in 0..n {
                        self.number()?;
                    }
                }
                Ok(())
            }
            // GENERICINST (CLASS | VALUETYPE) type count args.
            0x15 => {
                match self.byte()? {
                    0x11 | 0x12 => self.type_def_or_ref(out)?,
                    other => return Err(ClrError::BadOpcode(u16::from(other))),
                }
                let n = self.number()?;
                for _ in 0..n {
                    self.ty(out, depth + 1)?;
                }
                Ok(())
            }
            // FNPTR: a whole method signature.
            0x1B => self.method(out, depth + 1),
            other => Err(ClrError::BadOpcode(u16::from(other))),
        }
    }

    /// A method signature (II.23.2.1 to 3): return type and parameters.
    pub(crate) fn method(&mut self, out: &mut Vec<Named>, depth: usize) -> Result<(), ClrError> {
        let conv = self.byte()?;
        if conv & 0x10 != 0 {
            self.number()?; // generic parameter count
        }
        let params = self.number()?;
        self.ret_or_param(out, depth)?;
        for _ in 0..params {
            if self.peek() == Some(0x41) {
                self.at += 1; // SENTINEL
            }
            self.ret_or_param(out, depth)?;
        }
        Ok(())
    }

    /// A method definition's signature, as the first type each parameter names (`None` for
    /// one that names none: a primitive, a generic parameter).
    pub(crate) fn params(&mut self) -> Result<Vec<Option<Named>>, ClrError> {
        let conv = self.byte()?;
        if conv & 0x10 != 0 {
            self.number()?;
        }
        let count = self.number()?;
        let mut sink = Vec::new();
        self.ret_or_param(&mut sink, 0)?;
        let mut out = Vec::new();
        for _ in 0..count {
            let mut one = Vec::new();
            // Custom modifiers name types too; the parameter's own type comes after them.
            let mut mods = Vec::new();
            self.custom_mods(&mut mods)?;
            self.ret_or_param(&mut one, 0)?;
            out.push(one.first().copied());
        }
        Ok(out)
    }

    fn ret_or_param(&mut self, out: &mut Vec<Named>, depth: usize) -> Result<(), ClrError> {
        self.custom_mods(out)?;
        match self.peek() {
            // TYPEDBYREF, VOID.
            Some(0x16 | 0x01) => {
                self.at += 1;
                Ok(())
            }
            _ => self.ty(out, depth),
        }
    }

    /// A MethodSpec instantiation (II.23.2.15).
    pub(crate) fn instantiation(&mut self, out: &mut Vec<Named>) -> Result<(), ClrError> {
        if self.byte()? != 0x0A {
            return Err(ClrError::Truncated("method instantiation"));
        }
        let n = self.number()?;
        for _ in 0..n {
            self.ty(out, 1)?;
        }
        Ok(())
    }

    /// A field signature (II.23.2.4).
    pub(crate) fn field(&mut self, out: &mut Vec<Named>) -> Result<(), ClrError> {
        if self.byte()? != 0x06 {
            return Err(ClrError::Truncated("field signature"));
        }
        self.ty(out, 1)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn generic_arguments_and_arrays_are_collected() {
        // GENERICINST CLASS TypeRef#1 2 [VALUETYPE TypeDef#3, SZARRAY CLASS TypeRef#2]
        let b = [0x15, 0x12, 0x05, 0x02, 0x11, 0x0C, 0x1D, 0x12, 0x09];
        let mut out = Vec::new();
        Sig::new(&b).ty(&mut out, 0).unwrap();
        assert_eq!(
            out,
            [
                (table::TYPE_REF, 1),
                (table::TYPE_DEF, 3),
                (table::TYPE_REF, 2)
            ]
        );
    }

    #[test]
    fn a_truncated_or_unknown_signature_is_an_error() {
        let mut out = Vec::new();
        assert!(Sig::new(&[0x15, 0x12]).ty(&mut out, 0).is_err());
        assert!(Sig::new(&[0x7F]).ty(&mut out, 0).is_err());
        assert!(Sig::new(&[0x0A, 0x01]).instantiation(&mut out).is_err());
    }
}
