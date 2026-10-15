//! FIDO2 security keys (YubiKey etc.) as SSH keys: `sk-ssh-ed25519@openssh.com`.
//!
//! Wire formats follow OpenSSH's PROTOCOL.u2f. The authenticator signs
//! `sha256(application) || flags || counter || sha256(data)`; ctap-hid-fido2 hashes the
//! challenge for us, so we pass the raw SSH data-to-sign as the challenge.

use ctap_hid_fido2::fidokey::get_assertion::get_assertion_params::GetAssertionArgsBuilder;
use ctap_hid_fido2::fidokey::make_credential::make_credential_params::{
    CredentialSupportedKeyType, MakeCredentialArgsBuilder,
};
use ctap_hid_fido2::{FidoKeyHid, LibCfg};
use russh::keys::ssh_key::private::{KeypairData, SkEd25519 as SkEd25519Keypair};
use russh::keys::ssh_key::public::{Ed25519PublicKey, KeyData, SkEd25519};
use russh::keys::ssh_key::{LineEnding, PrivateKey, PublicKey};

/// OpenSSH's default application string for SSH keys on FIDO devices.
pub const DEFAULT_APPLICATION: &str = "ssh:";

/// OpenSSH sk flag: require user presence (touch) for every signature.
const SK_USER_PRESENCE_REQD: u8 = 0x01;

#[derive(Debug, thiserror::Error)]
pub enum FidoError {
    #[error("no FIDO2 security key found")]
    NoDevice,
    #[error("security key: {0}")]
    Device(String),
    #[error("unexpected response from security key: {0}")]
    Protocol(&'static str),
    #[error("key encoding: {0}")]
    Encoding(#[from] russh::keys::ssh_key::Error),
}

fn device_err(e: impl std::fmt::Display) -> FidoError {
    FidoError::Device(e.to_string())
}

/// A FIDO2-backed SSH key. Only the credential id (key handle) is stored on the host;
/// the private key never leaves the authenticator.
#[derive(Clone, Debug)]
pub struct SkKey {
    pub application: String,
    pub credential_id: Vec<u8>,
    pub public_key: PublicKey,
}

impl SkKey {
    /// Serialises as an OpenSSH private key file (key handle only), compatible with `ssh -i`.
    pub fn to_openssh(&self) -> Result<String, FidoError> {
        let KeyData::SkEd25519(public) = self.public_key.key_data() else {
            return Err(FidoError::Protocol("not an sk-ed25519 key"));
        };
        let keypair = SkEd25519Keypair::new(public.clone(), SK_USER_PRESENCE_REQD, self.credential_id.clone())?;
        let private = PrivateKey::new(KeypairData::SkEd25519(keypair), self.public_key.comment().clone())?;
        Ok(private.to_openssh(LineEnding::LF)?.to_string())
    }

    /// Parses an OpenSSH `sk-ssh-ed25519` private key file.
    pub fn from_openssh(pem: &str) -> Result<Self, FidoError> {
        let private = PrivateKey::from_openssh(pem)?;
        let KeypairData::SkEd25519(sk) = private.key_data() else {
            return Err(FidoError::Protocol("not an sk-ed25519 key"));
        };
        Ok(Self {
            application: sk.public().application().to_string(),
            credential_id: sk.key_handle().to_vec(),
            public_key: private.public_key().clone(),
        })
    }
}

fn open_device() -> Result<FidoKeyHid, FidoError> {
    // TODO: let the user pick when several keys are plugged in; use the first for now.
    let device = ctap_hid_fido2::get_fidokey_devices().into_iter().next().ok_or(FidoError::NoDevice)?;
    FidoKeyHid::new(&[device.param], &LibCfg::init()).map_err(device_err)
}

/// Creates a new ed25519 credential on the security key. Blocks until the user touches it.
pub fn generate_ed25519(application: &str, comment: &str, pin: Option<&str>) -> Result<SkKey, FidoError> {
    let device = open_device()?;
    // The attestation itself is not verified for SSH use, but the challenge should still be fresh.
    let mut challenge = [0u8; 32];
    getrandom::fill(&mut challenge).map_err(device_err)?;
    let mut args =
        MakeCredentialArgsBuilder::new(application, &challenge).key_type(CredentialSupportedKeyType::Ed25519);
    args = match pin {
        Some(pin) => args.pin(pin),
        None => args.without_pin_and_uv(),
    };
    let attestation = device.make_credential_with_args(&args.build()).map_err(device_err)?;

    // credential_publickey.der is a SubjectPublicKeyInfo; the raw key is the last 32 bytes.
    let der = &attestation.credential_publickey.der;
    let raw: [u8; 32] = der
        .get(der.len().saturating_sub(32)..)
        .and_then(|s| s.try_into().ok())
        .ok_or(FidoError::Protocol("ed25519 public key"))?;
    let public = SkEd25519::new(Ed25519PublicKey(raw), application);
    let mut public_key = PublicKey::from(KeyData::SkEd25519(public));
    public_key.set_comment(comment);

    Ok(SkKey { application: application.to_string(), credential_id: attestation.credential_descriptor.id, public_key })
}

/// Raw assertion pieces needed for an SSH sk signature.
pub struct SkSignature {
    pub signature: Vec<u8>,
    pub flags: u8,
    pub counter: u32,
}

impl SkSignature {
    /// Encodes the SSH signature blob: string alg, string sig, byte flags, uint32 counter.
    pub fn to_ssh_blob(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + 26 + 4 + self.signature.len() + 5);
        put_string(&mut out, b"sk-ssh-ed25519@openssh.com");
        put_string(&mut out, &self.signature);
        out.push(self.flags);
        out.extend_from_slice(&self.counter.to_be_bytes());
        out
    }
}

/// Signs `data` with the credential. Blocks until the user touches the key.
pub fn sign(key: &SkKey, data: &[u8], pin: Option<&str>) -> Result<SkSignature, FidoError> {
    let device = open_device()?;
    let mut args = GetAssertionArgsBuilder::new(&key.application, data).credential_id(&key.credential_id);
    args = match pin {
        Some(pin) => args.pin(pin),
        None => args.without_pin_and_uv(),
    };
    let assertion = device
        .get_assertion_with_args(&args.build())
        .map_err(device_err)?
        .into_iter()
        .next()
        .ok_or(FidoError::Protocol("no assertion"))?;
    // authenticatorData = rpIdHash(32) || flags(1) || signCount(4) || ...
    let flags = *assertion.auth_data.get(32).ok_or(FidoError::Protocol("auth data"))?;
    Ok(SkSignature { signature: assertion.signature, flags, counter: assertion.sign_count })
}

fn put_string(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// russh signer for publickey auth. The touch prompt blocks, so signing runs off the
/// async workers.
pub struct SkSigner {
    pub key: SkKey,
    pub pin: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum SkAuthError {
    #[error(transparent)]
    Fido(#[from] FidoError),
    #[error("ssh: {0}")]
    Send(#[from] russh::SendError),
}

impl russh::Signer for SkSigner {
    type Error = SkAuthError;

    fn auth_sign(
        &mut self,
        _key: &russh::keys::agent::AgentIdentity,
        _hash_alg: Option<russh::keys::HashAlg>,
        mut to_sign: Vec<u8>,
    ) -> impl Future<Output = Result<Vec<u8>, SkAuthError>> + Send {
        let (key, pin) = (self.key.clone(), self.pin.clone());
        async move {
            let data = to_sign.clone();
            let sig = tokio::task::spawn_blocking(move || sign(&key, &data, pin.as_deref()))
                .await
                .map_err(|e| FidoError::Device(e.to_string()))??;
            // russh expects the signed buffer with the signature blob appended as an SSH string.
            put_string(&mut to_sign, &sig.to_ssh_blob());
            Ok(to_sign)
        }
    }
}
