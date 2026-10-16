//! Vault encryption. Every device holds the same random 256-bit vault key; files are sealed
//! with XChaCha20-Poly1305, so a storage provider sees only ciphertext and cannot alter it
//! undetected. The key is shown to the user as a "sync code" to set up more devices.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use sha2::{Digest, Sha256};

use crate::SyncError;

const MAGIC: &[u8] = b"TMXS\x01";
const CODE_ALPHABET: &[u8; 32] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

#[derive(Clone, PartialEq, Eq)]
pub struct VaultKey([u8; 32]);

impl std::fmt::Debug for VaultKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VaultKey(…)")
    }
}

impl VaultKey {
    pub fn generate() -> Result<Self, SyncError> {
        let mut key = [0u8; 32];
        getrandom::fill(&mut key).map_err(|e| SyncError::Crypto(e.to_string()))?;
        Ok(Self(key))
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SyncError> {
        Ok(Self(bytes.try_into().map_err(|_| SyncError::Crypto("vault key must be 32 bytes".into()))?))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Sync code: the key plus a 2-byte checksum in an unambiguous base32 alphabet
    /// (no 0/O, 1/I), grouped by four: `ABCD-EFGH-…` (14 groups).
    pub fn to_code(&self) -> String {
        let checksum = Sha256::digest(self.0);
        let bytes: Vec<u8> = self.0.iter().chain(&checksum[..2]).copied().collect();
        let chars = base32(&bytes);
        chars.as_bytes().chunks(4).map(|c| std::str::from_utf8(c).unwrap()).collect::<Vec<_>>().join("-")
    }

    /// Parses a sync code; tolerates spaces, dashes and lowercase.
    pub fn from_code(code: &str) -> Result<Self, SyncError> {
        let cleaned: String =
            code.chars().filter(|c| !c.is_whitespace() && *c != '-').map(|c| c.to_ascii_uppercase()).collect();
        let bytes = unbase32(&cleaned).ok_or(SyncError::InvalidCode)?;
        if bytes.len() != 34 {
            return Err(SyncError::InvalidCode);
        }
        let (key, checksum) = bytes.split_at(32);
        if Sha256::digest(key)[..2] != *checksum {
            return Err(SyncError::InvalidCode);
        }
        Self::from_bytes(key)
    }

    pub fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>, SyncError> {
        let mut nonce = [0u8; 24];
        getrandom::fill(&mut nonce).map_err(|e| SyncError::Crypto(e.to_string()))?;
        let cipher = XChaCha20Poly1305::new((&self.0).into());
        let sealed = cipher
            .encrypt(&XNonce::from(nonce), Payload { msg: plaintext, aad: MAGIC })
            .map_err(|_| SyncError::Crypto("encryption failed".into()))?;
        Ok([MAGIC, &nonce, &sealed].concat())
    }

    pub fn open(&self, data: &[u8]) -> Result<Vec<u8>, SyncError> {
        let rest = data.strip_prefix(MAGIC).ok_or(SyncError::NotAVault)?;
        if rest.len() < 24 {
            return Err(SyncError::NotAVault);
        }
        let (nonce, sealed) = rest.split_at(24);
        let cipher = XChaCha20Poly1305::new((&self.0).into());
        cipher
            .decrypt(&XNonce::try_from(nonce).map_err(|_| SyncError::NotAVault)?, Payload { msg: sealed, aad: MAGIC })
            .map_err(|_| SyncError::WrongKey)
    }
}

fn base32(bytes: &[u8]) -> String {
    let mut out = String::new();
    let (mut buffer, mut bits) = (0u32, 0);
    for &b in bytes {
        buffer = (buffer << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(CODE_ALPHABET[((buffer >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(CODE_ALPHABET[((buffer << (5 - bits)) & 31) as usize] as char);
    }
    out
}

fn unbase32(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let (mut buffer, mut bits) = (0u32, 0);
    for c in text.bytes() {
        let value = CODE_ALPHABET.iter().position(|&a| a == c)? as u32;
        buffer = (buffer << 5) | value;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_round_trip_and_checksum() {
        let key = VaultKey::generate().unwrap();
        let code = key.to_code();
        assert_eq!(code.split('-').count(), 14);
        assert_eq!(VaultKey::from_code(&code).unwrap(), key);
        assert_eq!(VaultKey::from_code(&code.to_lowercase().replace('-', " ")).unwrap(), key);

        // A single typo is caught by the checksum.
        let mut typo: Vec<char> = code.chars().collect();
        typo[0] = if typo[0] == 'A' { 'B' } else { 'A' };
        assert!(matches!(VaultKey::from_code(&typo.into_iter().collect::<String>()), Err(SyncError::InvalidCode)));
        assert!(matches!(VaultKey::from_code("hello"), Err(SyncError::InvalidCode)));
    }

    #[test]
    fn seal_open_and_tamper_detection() {
        let key = VaultKey::generate().unwrap();
        let sealed = key.seal(b"secret hosts").unwrap();
        assert_eq!(key.open(&sealed).unwrap(), b"secret hosts");
        assert!(!sealed.windows(6).any(|w| w == b"secret"), "ciphertext only");

        let mut tampered = sealed.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(matches!(key.open(&tampered), Err(SyncError::WrongKey)));
        assert!(matches!(VaultKey::generate().unwrap().open(&sealed), Err(SyncError::WrongKey)));
        assert!(matches!(key.open(b"plain"), Err(SyncError::NotAVault)));
    }
}
