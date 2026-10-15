//! Core data model shared by every platform.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthMethod {
    Password,
    /// Reference to a key stored in the key manager; never the key material itself.
    Key { key_id: Uuid },
    Agent,
    KeyboardInteractive,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Host {
    pub id: Uuid,
    pub label: String,
    pub hostname: String,
    pub port: u16,
    pub username: String,
    pub auth: AuthMethod,
    /// Hosts to hop through, in order (ProxyJump).
    pub jump_hosts: Vec<Uuid>,
    pub keepalive_secs: u32,
}

impl Host {
    pub fn new(label: impl Into<String>, hostname: impl Into<String>, username: impl Into<String>) -> Self {
        Self {
            id: Uuid::new_v4(),
            label: label.into(),
            hostname: hostname.into(),
            port: 22,
            username: username.into(),
            auth: AuthMethod::Password,
            jump_hosts: Vec::new(),
            keepalive_secs: 30,
        }
    }
}
