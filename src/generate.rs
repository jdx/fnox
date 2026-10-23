//! Cryptographically random secret generation for `fnox set --generate`.

use crate::error::{FnoxError, Result};
use strum::{Display, EnumString};

/// Default number of characters for generated values.
pub const DEFAULT_LENGTH: usize = 32;
/// Upper bound on `--length`, to catch typos before allocating.
pub const MAX_LENGTH: usize = 4096;

const URL_SAFE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

#[derive(Clone, Copy, Debug, PartialEq, Eq, usage_rs::ValueEnum, Display, EnumString)]
#[strum(serialize_all = "lowercase")]
pub enum GenerateKind {
    /// URL-safe characters: letters, digits, `-` and `_`
    Password,
    /// Lowercase hexadecimal
    Hex,
    /// URL-safe base64 without padding
    Base64,
    /// Random (version 4) UUID; ignores `--length`
    Uuid,
}

/// Generate a random value of `kind`. `length` counts output characters.
pub fn generate(kind: GenerateKind, length: usize) -> Result<String> {
    if kind == GenerateKind::Uuid {
        return Ok(uuid_v4());
    }
    if length == 0 || length > MAX_LENGTH {
        return Err(FnoxError::Config(format!(
            "--length must be between 1 and {MAX_LENGTH}, got {length}"
        )));
    }
    Ok(match kind {
        GenerateKind::Password => {
            // 64 symbols divide 256 evenly, so masking a random byte is unbiased.
            let mut bytes = vec![0u8; length];
            rand::fill(&mut bytes[..]);
            bytes
                .iter()
                .map(|b| URL_SAFE[(b & 0x3f) as usize] as char)
                .collect()
        }
        GenerateKind::Hex => {
            let mut bytes = vec![0u8; length.div_ceil(2)];
            rand::fill(&mut bytes[..]);
            let mut out = hex::encode(bytes);
            out.truncate(length);
            out
        }
        GenerateKind::Base64 => {
            let mut bytes = vec![0u8; (length * 3).div_ceil(4)];
            rand::fill(&mut bytes[..]);
            let mut out = data_encoding::BASE64URL_NOPAD.encode(&bytes);
            out.truncate(length);
            out
        }
        GenerateKind::Uuid => unreachable!(),
    })
}

fn uuid_v4() -> String {
    let mut b = [0u8; 16];
    rand::fill(&mut b);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h = hex::encode(b);
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn lengths_are_exact_for_every_edge() {
        for kind in [
            GenerateKind::Password,
            GenerateKind::Hex,
            GenerateKind::Base64,
        ] {
            for len in [1, 2, 3, 4, 5, 31, 32, 33, MAX_LENGTH] {
                assert_eq!(generate(kind, len).unwrap().len(), len, "{kind} {len}");
            }
        }
    }

    #[test]
    fn charsets() {
        let p = generate(GenerateKind::Password, 512).unwrap();
        assert!(p.bytes().all(|c| URL_SAFE.contains(&c)));
        let h = generate(GenerateKind::Hex, 101).unwrap();
        assert!(
            h.bytes()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
        let b = generate(GenerateKind::Base64, 101).unwrap();
        assert!(b.bytes().all(|c| URL_SAFE.contains(&c)));
    }

    #[test]
    fn uuid_shape() {
        let u = generate(GenerateKind::Uuid, DEFAULT_LENGTH).unwrap();
        assert_eq!(u.len(), 36);
        assert_eq!(&u[14..15], "4");
        assert!("89ab".contains(&u[19..20]));
    }

    #[test]
    fn values_are_unique() {
        for kind in [
            GenerateKind::Password,
            GenerateKind::Hex,
            GenerateKind::Base64,
            GenerateKind::Uuid,
        ] {
            let set: HashSet<_> = (0..64).map(|_| generate(kind, 32).unwrap()).collect();
            assert_eq!(set.len(), 64, "{kind}");
        }
    }

    #[test]
    fn rejects_zero_and_absurd_lengths() {
        assert!(generate(GenerateKind::Password, 0).is_err());
        assert!(generate(GenerateKind::Hex, MAX_LENGTH + 1).is_err());
        assert!(generate(GenerateKind::Base64, usize::MAX).is_err());
    }
}
