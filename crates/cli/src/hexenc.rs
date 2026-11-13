//! Lowercase hex, as digests and content hashes are written everywhere in the CLI.

/// Bytes as lowercase hex, two digits each.
pub(crate) trait ToHex {
    fn to_hex(&self) -> String;
}

impl<T: AsRef<[u8]> + ?Sized> ToHex for T {
    fn to_hex(&self) -> String {
        const DIGITS: &[u8; 16] = b"0123456789abcdef";
        let bytes = self.as_ref();
        let mut out = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            out.push(char::from(DIGITS[usize::from(b >> 4)]));
            out.push(char::from(DIGITS[usize::from(b & 0x0f)]));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::ToHex;

    #[test]
    fn matches_two_digit_lowercase_formatting() {
        let bytes: Vec<u8> = (0..=255).collect();
        let expected: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(bytes.to_hex(), expected);
        assert_eq!([0u8; 0].to_hex(), "");
    }
}
