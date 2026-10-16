//! FIDO2 security keys (YubiKey etc.) as SSH keys: `sk-ssh-ed25519@openssh.com`.
//!
//! Wire formats follow OpenSSH's PROTOCOL.u2f. The authenticator signs
//! `sha256(application) || flags || counter || sha256(data)`; ctap-hid-fido2 hashes the
//! challenge for us, so we pass the raw SSH data-to-sign as the challenge.
//!
//! USB HID access exists on desktop platforms only. iOS has no HID backend; there the app
//! talks to the key through YubiKit and signs via the core's external-signer path.

use russh::keys::ssh_key::private::{KeypairData, SkEd25519 as SkEd25519Keypair};
use russh::keys::ssh_key::public::KeyData;
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
    #[error("the security key needs its PIN")]
    PinRequired,
    #[error("wrong security key PIN")]
    PinInvalid,
    #[error("the security key PIN is blocked; reset it with the vendor tool")]
    PinBlocked,
    #[error("timed out waiting for a touch on the security key")]
    Timeout,
    #[error("unexpected response from security key: {0}")]
    Protocol(&'static str),
    #[error("key encoding: {0}")]
    Encoding(#[from] russh::keys::ssh_key::Error),
}

/// Maps CTAP2 status codes (only exposed in ctap-hid-fido2's error text) to typed errors.
#[cfg(not(target_os = "ios"))]
fn device_err(e: impl std::fmt::Display) -> FidoError {
    let message = e.to_string();
    let has = |code: &str| message.contains(code);
    if has("0x36") {
        FidoError::PinRequired
    } else if has("0x31") {
        FidoError::PinInvalid
    } else if has("0x32") || has("0x34") {
        FidoError::PinBlocked
    } else if has("0x3A") || has("0x2F") {
        FidoError::Timeout
    } else {
        FidoError::Device(message)
    }
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

#[cfg(not(target_os = "ios"))]
mod hid {
    use ctap_hid_fido2::fidokey::get_assertion::get_assertion_params::GetAssertionArgsBuilder;
    use ctap_hid_fido2::fidokey::make_credential::make_credential_params::{
        CredentialSupportedKeyType, MakeCredentialArgsBuilder,
    };
    use ctap_hid_fido2::{FidoKeyHid, LibCfg};
    use russh::keys::ssh_key::PublicKey;
    use russh::keys::ssh_key::public::{Ed25519PublicKey, KeyData, SkEd25519};

    use super::{FidoError, SkKey, SkSignature, device_err};

    fn open_device() -> Result<FidoKeyHid, FidoError> {
        // TODO: let the user pick when several keys are plugged in; use the first for now.
        let device = ctap_hid_fido2::get_fidokey_devices().into_iter().next().ok_or(FidoError::NoDevice)?;
        FidoKeyHid::new(&[device.param], &LibCfg::init()).map_err(device_err)
    }

    /// Blocks until the user touches the key.
    pub(super) fn generate_ed25519(application: &str, comment: &str, pin: Option<&str>) -> Result<SkKey, FidoError> {
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

        Ok(SkKey {
            application: application.to_string(),
            credential_id: attestation.credential_descriptor.id,
            public_key,
        })
    }

    /// Blocks until the user touches the key.
    pub(super) fn sign(key: &SkKey, data: &[u8], pin: Option<&str>) -> Result<SkSignature, FidoError> {
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
}

#[cfg(target_os = "ios")]
mod hid {
    use super::{FidoError, SkKey, SkSignature};

    pub(super) fn generate_ed25519(_: &str, _: &str, _: Option<&str>) -> Result<SkKey, FidoError> {
        Err(FidoError::NoDevice)
    }

    pub(super) fn sign(_: &SkKey, _: &[u8], _: Option<&str>) -> Result<SkSignature, FidoError> {
        Err(FidoError::NoDevice)
    }
}

/// Creates a new ed25519 credential on the security key. Blocks until the user touches it.
pub fn generate_ed25519(application: &str, comment: &str, pin: Option<&str>) -> Result<SkKey, FidoError> {
    hid::generate_ed25519(application, comment, pin)
}

/// Signs `data` with the credential. Blocks until the user touches the key.
pub fn sign(key: &SkKey, data: &[u8], pin: Option<&str>) -> Result<SkSignature, FidoError> {
    hid::sign(key, data, pin)
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
    /// Asked (blocking) when the key requires a PIN; the argument explains why.
    pub ask_pin: Option<PinPrompt>,
}

pub type PinPrompt = std::sync::Arc<dyn Fn(&str) -> Option<String> + Send + Sync>;

/// Signs, asking for the PIN when the key demands one (up to three attempts).
pub fn sign_with_prompt(
    key: &SkKey,
    data: &[u8],
    mut pin: Option<String>,
    ask_pin: Option<&PinPrompt>,
) -> Result<SkSignature, FidoError> {
    for _ in 0..3 {
        match sign(key, data, pin.as_deref()) {
            Err(e @ (FidoError::PinRequired | FidoError::PinInvalid)) => {
                let reason = if matches!(e, FidoError::PinInvalid) {
                    "Wrong PIN, try again"
                } else {
                    "Enter the security key PIN"
                };
                pin = Some(ask_pin.and_then(|ask| ask(reason)).ok_or(e)?);
            }
            other => return other,
        }
    }
    Err(FidoError::PinInvalid)
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
        let (key, pin, ask_pin) = (self.key.clone(), self.pin.clone(), self.ask_pin.clone());
        async move {
            let data = to_sign.clone();
            let sig = tokio::task::spawn_blocking(move || sign_with_prompt(&key, &data, pin, ask_pin.as_ref()))
                .await
                .map_err(|e| FidoError::Device(e.to_string()))??;
            // russh expects the signed buffer with the signature blob appended as an SSH string.
            put_string(&mut to_sign, &sig.to_ssh_blob());
            Ok(to_sign)
        }
    }
}
