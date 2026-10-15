//! Core data model shared by every platform.
//!
//! Records carry stable UUIDs and an `updated_at` timestamp so they can later be merged
//! across devices. Secrets are never part of the model: records hold a [`SecretRef`] and
//! the platform secret store (Keychain etc.) holds the value.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Milliseconds since the Unix epoch.
pub type Timestamp = i64;

pub fn now() -> Timestamp {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as Timestamp).unwrap_or(0)
}

/// Opaque handle to a value in the platform secret store.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SecretRef(pub String);

impl SecretRef {
    pub fn new() -> Self {
        Self(Uuid::new_v4().to_string())
    }
}

impl Default for SecretRef {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AuthMethod {
    /// Password kept in the secret store; `None` means ask every time.
    Password {
        secret: Option<SecretRef>,
    },
    /// A key from the key manager.
    Key {
        key_id: Uuid,
    },
    /// Whatever the running ssh-agent offers (direct build only).
    Agent,
    KeyboardInteractive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ForwardKind {
    /// -L: listen locally, connect from the server.
    Local,
    /// -R: listen on the server, connect from here.
    Remote,
    /// -D: SOCKS proxy.
    Dynamic,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortForward {
    pub id: Uuid,
    pub kind: ForwardKind,
    pub bind_host: String,
    pub bind_port: u16,
    /// Unused for dynamic forwards.
    pub target_host: String,
    pub target_port: u16,
    pub auto_start: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Host {
    pub id: Uuid,
    pub label: String,
    pub group_id: Option<Uuid>,
    #[serde(default)]
    pub tags: Vec<String>,
    pub hostname: String,
    pub port: u16,
    pub username: String,
    pub auth: AuthMethod,
    /// Hosts to hop through, in order (ProxyJump).
    #[serde(default)]
    pub jump_hosts: Vec<Uuid>,
    #[serde(default)]
    pub forwards: Vec<PortForward>,
    pub startup_command: Option<String>,
    #[serde(default)]
    pub env: Vec<(String, String)>,
    pub keepalive_secs: u32,
    pub term: String,
    pub theme_id: Option<Uuid>,
    pub updated_at: Timestamp,
}

impl Host {
    pub fn new(label: impl Into<String>, hostname: impl Into<String>, username: impl Into<String>) -> Self {
        Self {
            id: Uuid::new_v4(),
            label: label.into(),
            group_id: None,
            tags: Vec::new(),
            hostname: hostname.into(),
            port: 22,
            username: username.into(),
            auth: AuthMethod::Password { secret: None },
            jump_hosts: Vec::new(),
            forwards: Vec::new(),
            startup_command: None,
            env: Vec::new(),
            keepalive_secs: 30,
            term: "xterm-256color".into(),
            theme_id: None,
            updated_at: now(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Group {
    pub id: Uuid,
    pub name: String,
    pub parent_id: Option<Uuid>,
    pub updated_at: Timestamp,
}

impl Group {
    pub fn new(name: impl Into<String>) -> Self {
        Self { id: Uuid::new_v4(), name: name.into(), parent_id: None, updated_at: now() }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum KeyStorage {
    /// OpenSSH private key in the secret store; passphrase (if any) stored separately.
    Software { secret: SecretRef, passphrase: Option<SecretRef> },
    /// FIDO2 credential; the key handle file is not secret but lives in the store too.
    SecurityKey { key_handle: SecretRef },
    /// PIV slot on a smartcard, addressed by token + slot.
    Piv { token_id: String, slot: String },
    /// P-256 key bound to this device's Secure Enclave; never syncs.
    SecureEnclave { tag: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Key {
    pub id: Uuid,
    pub label: String,
    /// OpenSSH public key line (`ssh-ed25519 AAAA… comment`).
    pub public_key: String,
    pub storage: KeyStorage,
    pub updated_at: Timestamp,
}

/// Outcome of looking a server key up in known_hosts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostKeyStatus {
    Trusted,
    /// Never seen this host (with this algorithm) before.
    Unknown,
    /// We have a different key on record: possible MITM, must not connect silently.
    Changed {
        previous_fingerprint: String,
    },
}
