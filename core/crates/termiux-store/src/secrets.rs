//! Secret storage interface. Platforms implement it with their secure store
//! (Keychain on Apple, Keystore on Android, …); the in-memory version is for tests.

use std::collections::HashMap;
use std::sync::Mutex;

use termiux_model::SecretRef;

#[derive(Debug, thiserror::Error)]
pub enum SecretError {
    #[error("secret store unavailable: {0}")]
    Unavailable(String),
    #[error("access denied")]
    Denied,
}

pub trait SecretStore: Send + Sync {
    fn get(&self, secret: &SecretRef) -> Result<Option<Vec<u8>>, SecretError>;
    fn set(&self, secret: &SecretRef, value: &[u8]) -> Result<(), SecretError>;
    fn delete(&self, secret: &SecretRef) -> Result<(), SecretError>;
}

#[derive(Default)]
pub struct MemorySecretStore {
    values: Mutex<HashMap<SecretRef, Vec<u8>>>,
}

impl SecretStore for MemorySecretStore {
    fn get(&self, secret: &SecretRef) -> Result<Option<Vec<u8>>, SecretError> {
        Ok(self.values.lock().unwrap().get(secret).cloned())
    }

    fn set(&self, secret: &SecretRef, value: &[u8]) -> Result<(), SecretError> {
        self.values.lock().unwrap().insert(secret.clone(), value.to_vec());
        Ok(())
    }

    fn delete(&self, secret: &SecretRef) -> Result<(), SecretError> {
        self.values.lock().unwrap().remove(secret);
        Ok(())
    }
}
