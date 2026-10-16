//! SSH key generation and export, and conversion of signatures produced by hardware
//! (PIV smartcards, Secure Enclave) into SSH wire format.

use russh::keys::ssh_key::private::{KeypairData, RsaKeypair};
use russh::keys::ssh_key::{Algorithm, EcdsaCurve, LineEnding, PrivateKey};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum KeyError {
    #[error("key: {0}")]
    Key(String),
    #[error("wrong passphrase")]
    WrongPassphrase,
    #[error("malformed signature: {0}")]
    Signature(&'static str),
}

fn key_err(e: impl std::fmt::Display) -> KeyError {
    KeyError::Key(e.to_string())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
    Ed25519,
    EcdsaP256,
    EcdsaP384,
    Rsa { bits: usize },
}

/// Generates a new software key. RSA keys below 3072 bits are refused.
pub fn generate(kind: KeyType, comment: &str) -> Result<PrivateKey, KeyError> {
    let mut rng = rand::rng();
    let mut key = match kind {
        KeyType::Ed25519 => PrivateKey::random(&mut rng, Algorithm::Ed25519).map_err(key_err)?,
        KeyType::EcdsaP256 => {
            PrivateKey::random(&mut rng, Algorithm::Ecdsa { curve: EcdsaCurve::NistP256 }).map_err(key_err)?
        }
        KeyType::EcdsaP384 => {
            PrivateKey::random(&mut rng, Algorithm::Ecdsa { curve: EcdsaCurve::NistP384 }).map_err(key_err)?
        }
        KeyType::Rsa { bits } => {
            if bits < 3072 {
                return Err(KeyError::Key("RSA keys must be at least 3072 bits".into()));
            }
            let keypair = RsaKeypair::random(&mut rng, bits).map_err(key_err)?;
            PrivateKey::new(KeypairData::from(keypair), comment).map_err(key_err)?
        }
    };
    key.set_comment(comment);
    Ok(key)
}

/// OpenSSH private key file, encrypted when a non-empty passphrase is given.
pub fn to_openssh(key: &PrivateKey, passphrase: Option<&str>) -> Result<String, KeyError> {
    let key = match passphrase.filter(|p| !p.is_empty()) {
        Some(p) => key.encrypt(&mut rand::rng(), p).map_err(key_err)?,
        None => key.clone(),
    };
    Ok(key.to_openssh(LineEnding::LF).map_err(key_err)?.to_string())
}

/// Decrypts (if needed) and re-encodes a stored key for export.
pub fn export(
    openssh: &str,
    stored_passphrase: Option<&str>,
    export_passphrase: Option<&str>,
) -> Result<String, KeyError> {
    let mut key = PrivateKey::from_openssh(openssh).map_err(key_err)?;
    if key.is_encrypted() {
        key = key.decrypt(stored_passphrase.unwrap_or_default()).map_err(|_| KeyError::WrongPassphrase)?;
    }
    to_openssh(&key, export_passphrase)
}

fn put_string(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// SSH mpint: big-endian, minimal, with a leading zero if the top bit is set.
fn put_mpint(out: &mut Vec<u8>, unsigned: &[u8]) {
    let trimmed = &unsigned[unsigned.iter().position(|&b| b != 0).unwrap_or(unsigned.len())..];
    let mut value = Vec::with_capacity(trimmed.len() + 1);
    if trimmed.first().is_some_and(|b| b & 0x80 != 0) {
        value.push(0);
    }
    value.extend_from_slice(trimmed);
    put_string(out, &value);
}

/// Reads one DER INTEGER, returning (unsigned big-endian value, rest).
fn der_integer(input: &[u8]) -> Result<(&[u8], &[u8]), KeyError> {
    let [0x02, len, rest @ ..] = input else { return Err(KeyError::Signature("expected INTEGER")) };
    let len = *len as usize;
    if len > 0x7f || rest.len() < len {
        return Err(KeyError::Signature("bad INTEGER length"));
    }
    Ok((&rest[..len], &rest[len..]))
}

/// Converts an X9.62 DER ECDSA signature (`SEQUENCE { r INTEGER, s INTEGER }`, as returned
/// by Security.framework / CryptoKit / PIV cards) to an SSH signature blob.
pub fn ecdsa_der_to_ssh(der: &[u8], curve: EcdsaCurve) -> Result<Vec<u8>, KeyError> {
    let body = match der {
        [0x30, len, rest @ ..] if (*len as usize) == rest.len() && *len < 0x80 => rest,
        [0x30, 0x81, len, rest @ ..] if (*len as usize) == rest.len() => rest,
        _ => return Err(KeyError::Signature("expected SEQUENCE")),
    };
    let (r, rest) = der_integer(body)?;
    let (s, rest) = der_integer(rest)?;
    if !rest.is_empty() {
        return Err(KeyError::Signature("trailing data"));
    }
    let mut inner = Vec::new();
    put_mpint(&mut inner, r);
    put_mpint(&mut inner, s);
    let mut blob = Vec::new();
    put_string(&mut blob, Algorithm::Ecdsa { curve }.as_str().as_bytes());
    put_string(&mut blob, &inner);
    Ok(blob)
}

/// Wraps a PKCS#1 v1.5 SHA-512 RSA signature as an `rsa-sha2-512` SSH signature blob.
pub fn rsa_sha512_to_ssh(signature: &[u8]) -> Vec<u8> {
    let mut blob = Vec::new();
    put_string(&mut blob, b"rsa-sha2-512");
    put_string(&mut blob, signature);
    blob
}

#[cfg(test)]
mod tests {
    use russh::keys::ssh_key::{HashAlg, SshSig};

    use super::*;

    #[test]
    fn generates_each_type_and_round_trips() {
        for (kind, alg) in [
            (KeyType::Ed25519, "ssh-ed25519"),
            (KeyType::EcdsaP256, "ecdsa-sha2-nistp256"),
            (KeyType::EcdsaP384, "ecdsa-sha2-nistp384"),
        ] {
            let key = generate(kind, "me@test").unwrap();
            let file = to_openssh(&key, None).unwrap();
            let parsed = PrivateKey::from_openssh(&file).unwrap();
            assert_eq!(parsed.public_key(), key.public_key());
            assert!(parsed.public_key().to_openssh().unwrap().starts_with(alg));
            assert_eq!(parsed.comment().as_str_lossy(), "me@test");
        }
    }

    #[test]
    fn rsa_size_floor() {
        assert!(generate(KeyType::Rsa { bits: 2048 }, "x").is_err());
    }

    #[test]
    fn encrypted_export_and_reexport() {
        let key = generate(KeyType::Ed25519, "c").unwrap();
        let encrypted = to_openssh(&key, Some("pw")).unwrap();
        assert!(PrivateKey::from_openssh(&encrypted).unwrap().is_encrypted());
        assert_eq!(export(&encrypted, Some("bad"), None), Err(KeyError::WrongPassphrase));
        let plain = export(&encrypted, Some("pw"), None).unwrap();
        let parsed = PrivateKey::from_openssh(&plain).unwrap();
        assert!(!parsed.is_encrypted());
        assert_eq!(parsed.public_key(), key.public_key());
    }

    #[test]
    fn mpint_encoding() {
        let mut out = Vec::new();
        put_mpint(&mut out, &[0x00, 0x00, 0x7f]);
        assert_eq!(out, [0, 0, 0, 1, 0x7f]);
        out.clear();
        put_mpint(&mut out, &[0x80, 0x01]);
        assert_eq!(out, [0, 0, 0, 3, 0x00, 0x80, 0x01]);
    }

    #[test]
    fn der_conversion_matches_ssh_signer() {
        // Sign with a real P-256 key via ssh-key, re-encode the (r, s) pair as DER, and check
        // our conversion produces the identical SSH blob.
        let key = generate(KeyType::EcdsaP256, "").unwrap();
        let sig = SshSig::sign(&key, "test", HashAlg::Sha256, b"hello").unwrap();
        let ssh_blob = sig.signature();
        let raw = ssh_blob.as_bytes();
        // raw = mpint r || mpint s
        let read = |b: &[u8]| {
            let n = u32::from_be_bytes(b[..4].try_into().unwrap()) as usize;
            (b[4..4 + n].to_vec(), b[4 + n..].to_vec())
        };
        let (r, rest) = read(raw);
        let (s, _) = read(&rest);
        let der_int = |v: &[u8]| [vec![0x02, v.len() as u8], v.to_vec()].concat();
        let body = [der_int(&r), der_int(&s)].concat();
        let der = [vec![0x30, body.len() as u8], body].concat();

        let blob = ecdsa_der_to_ssh(&der, EcdsaCurve::NistP256).unwrap();
        let mut expected = Vec::new();
        put_string(&mut expected, b"ecdsa-sha2-nistp256");
        put_string(&mut expected, raw);
        assert_eq!(blob, expected);
    }

    #[test]
    fn rejects_garbage_der() {
        assert!(ecdsa_der_to_ssh(&[0x30, 0x02, 0x05, 0x00], EcdsaCurve::NistP256).is_err());
        assert!(ecdsa_der_to_ssh(b"nope", EcdsaCurve::NistP256).is_err());
    }
}
