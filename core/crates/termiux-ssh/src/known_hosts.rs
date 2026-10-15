//! known_hosts policy: trust on first use (with a prompt), hard failure on change.

use std::sync::Arc;

use russh::keys::{HashAlg, PublicKey};
use termiux_model::HostKeyStatus;
use termiux_store::{KnownHostKey, Store};

use crate::{HostKeyError, HostKeyVerifier};

/// What the user is shown when a host is seen for the first time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostKeyInfo {
    pub host: String,
    pub port: u16,
    pub algorithm: String,
    pub fingerprint: String,
}

/// Asks the user whether to trust a host seen for the first time. May block.
pub trait NewHostPrompt: Send + Sync + 'static {
    fn confirm_new_host(&self, info: &HostKeyInfo) -> bool;
}

/// Store-backed verifier. A changed key is never accepted here: the UI must explain the
/// risk and call [`Store::forget_host`] explicitly before reconnecting.
pub struct KnownHostsVerifier {
    pub store: Arc<Store>,
    pub prompt: Arc<dyn NewHostPrompt>,
}

impl HostKeyVerifier for KnownHostsVerifier {
    fn known_key_types(&self, host: &str, port: u16) -> Vec<String> {
        self.store
            .known_host_keys(host, port)
            .map(|keys| keys.into_iter().map(|k| k.algorithm).collect())
            .unwrap_or_default()
    }

    fn verify(&self, host: &str, port: u16, key: &PublicKey) -> Result<(), HostKeyError> {
        let internal = |e: &dyn std::fmt::Display| HostKeyError::Internal(e.to_string());
        let fingerprint = key.fingerprint(HashAlg::Sha256).to_string();
        let openssh = key.to_openssh().map_err(|e| internal(&e))?;
        // "<algorithm> <base64> [comment]"
        let mut parts = openssh.split_whitespace();
        let record = KnownHostKey {
            algorithm: parts.next().unwrap_or_default().to_string(),
            public_key: parts.next().unwrap_or_default().to_string(),
            fingerprint: fingerprint.clone(),
        };

        match self.store.check_host_key(host, port, &record).map_err(|e| internal(&e))? {
            HostKeyStatus::Trusted => Ok(()),
            HostKeyStatus::Changed { previous_fingerprint } => {
                Err(HostKeyError::Changed { host: host.to_string(), fingerprint, previous_fingerprint })
            }
            HostKeyStatus::Unknown => {
                let info = HostKeyInfo {
                    host: host.to_string(),
                    port,
                    algorithm: record.algorithm.clone(),
                    fingerprint: fingerprint.clone(),
                };
                if !self.prompt.confirm_new_host(&info) {
                    return Err(HostKeyError::NotTrusted { host: host.to_string(), fingerprint });
                }
                self.store.trust_host_key(host, port, &record).map_err(|e| internal(&e))
            }
        }
    }
}
