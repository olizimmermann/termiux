//! End-to-end encrypted sync of hosts, keys, themes, known hosts and (optionally)
//! secrets between a user's devices, without a server of our own.
//!
//! Each device keeps a [`SyncState`] (field-level last-writer-wins records). A sync round:
//! 1. compares the local database with the state of the last round and stamps local changes,
//! 2. merges the states published by the other devices,
//! 3. applies the merged state to the local database and secret store,
//! 4. publishes its own state, encrypted with the vault key.
//!
//! Transports only move opaque encrypted blobs; [`FolderTransport`] uses a shared folder
//! (iCloud Drive, Dropbox, Syncthing…) with one file per device, so file syncing services
//! never see conflicting writes.

mod crypto;
mod state;

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use termiux_model::{AuthMethod, Key, KeyStorage, SecretRef};
use termiux_store::{KnownHostKey, SYNCED_TABLES, SecretStore, Store};

pub use crypto::VaultKey;
pub use state::{Clock, Entry, Field, Stamp, SyncState, entry_key};

#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    #[error("this is not a valid sync code")]
    InvalidCode,
    #[error("the sync data was encrypted with a different sync code")]
    WrongKey,
    #[error("not a Termiux sync file")]
    NotAVault,
    #[error("encryption: {0}")]
    Crypto(String),
    #[error("sync folder: {0}")]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Store(#[from] termiux_store::StoreError),
    #[error(transparent)]
    Secret(#[from] termiux_store::SecretError),
    #[error("corrupt sync data: {0}")]
    Json(#[from] serde_json::Error),
}

type Result<T> = std::result::Result<T, SyncError>;

const KNOWN_HOSTS: &str = "known_hosts";
const SECRETS: &str = "secrets";
const STATE_KEY: &str = "sync.state";
const DEVICE_KEY: &str = "sync.device";

/// Moves encrypted state blobs between devices.
pub trait Transport {
    /// Every device's latest published blob (may include our own).
    fn read_all(&self) -> Result<Vec<Vec<u8>>>;
    fn publish(&self, device: &str, blob: &[u8]) -> Result<()>;
}

/// One `<device>.termiux-sync` file per device in a shared folder.
pub struct FolderTransport {
    pub dir: PathBuf,
}

const FILE_EXTENSION: &str = "termiux-sync";

impl Transport for FolderTransport {
    fn read_all(&self) -> Result<Vec<Vec<u8>>> {
        let mut blobs = Vec::new();
        for entry in std::fs::read_dir(&self.dir)? {
            let path = entry?.path();
            if path.extension().is_some_and(|e| e == FILE_EXTENSION) {
                // A file mid-download by the cloud provider may be unreadable; skip it this round.
                if let Ok(blob) = std::fs::read(&path) {
                    blobs.push(blob);
                }
            }
        }
        Ok(blobs)
    }

    fn publish(&self, device: &str, blob: &[u8]) -> Result<()> {
        let target = self.dir.join(format!("{device}.{FILE_EXTENSION}"));
        // Write then rename, so readers never see a half-written file.
        let temp = self.dir.join(format!(".{device}.{FILE_EXTENSION}.tmp"));
        std::fs::write(&temp, blob)?;
        std::fs::rename(&temp, &target)?;
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
struct Published {
    device: String,
    state: SyncState,
}

/// Summary of a sync round.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SyncReport {
    /// Records created, changed or deleted locally by other devices.
    pub received: usize,
    /// Local changes recorded in this round.
    pub sent: usize,
    /// Number of other devices whose data was merged.
    pub devices: usize,
}

pub struct SyncEngine<'a> {
    pub store: &'a Store,
    pub secrets: &'a dyn SecretStore,
    pub key: &'a VaultKey,
    /// Also sync passwords and private keys (always end-to-end encrypted).
    pub include_secrets: bool,
}

/// This device's stable sync id (created on first use).
pub fn device_id(store: &Store) -> Result<String> {
    if let Some(id) = store.get_value(DEVICE_KEY)? {
        return Ok(String::from_utf8_lossy(&id).into_owned());
    }
    let id = uuid::Uuid::new_v4().to_string();
    store.set_value(DEVICE_KEY, id.as_bytes())?;
    Ok(id)
}

/// Forgets sync state (leaving the vault). Local data stays.
pub fn reset(store: &Store) -> Result<()> {
    store.delete_value(STATE_KEY)?;
    Ok(())
}

impl SyncEngine<'_> {
    pub fn sync(&self, transport: &dyn Transport) -> Result<SyncReport> {
        let device = device_id(self.store)?;
        let mut state: SyncState = match self.store.get_value(STATE_KEY)? {
            Some(bytes) => serde_json::from_slice(&bytes)?,
            None => SyncState::default(),
        };
        let mut clock = Clock::new(&device);
        if let Some(latest) = state.latest_stamp() {
            clock.observe(&latest.clone());
        }

        // 1. Local changes since the last round.
        let local = self.local_snapshot()?;
        let mut report = SyncReport::default();
        for (key, value) in &local {
            if state.record_local(key, value, &mut clock) {
                report.sent += 1;
            }
        }
        for key in self.owned_keys(&state) {
            if !local.contains_key(&key) && state.is_live(&key) {
                state.delete_local(&key, &mut clock);
                report.sent += 1;
            }
        }

        // 2. Merge everyone else.
        let before = state.clone();
        for blob in transport.read_all()? {
            // Files from another vault (or corrupted) are ignored rather than failing the round.
            let Ok(plain) = self.key.open(&blob) else { continue };
            let published: Published = serde_json::from_slice(&plain)?;
            if published.device != device {
                report.devices += 1;
            }
            state.merge(&published.state);
        }

        // 3. Apply what changed.
        report.received = self.apply(&before, &state)?;

        // 4. Persist and publish.
        self.store.set_value(STATE_KEY, &serde_json::to_vec(&state)?)?;
        let blob = self.key.seal(&serde_json::to_vec(&Published { device: device.clone(), state })?)?;
        transport.publish(&device, &blob)?;
        Ok(report)
    }

    /// Keys of the state that this device is responsible for diffing. Secrets are only
    /// diffed when secret sync is on, so turning it off never deletes others' secrets.
    fn owned_keys(&self, state: &SyncState) -> Vec<String> {
        state
            .entries
            .keys()
            .filter(|k| {
                self.include_secrets || !k.starts_with(&format!("{SECRETS}/")) || self.is_always_synced_secret(k)
            })
            .cloned()
            .collect()
    }

    fn is_always_synced_secret(&self, key: &str) -> bool {
        // FIDO2 key handles are only useful together with the hardware key.
        key.strip_prefix(&format!("{SECRETS}/"))
            .is_some_and(|id| self.key_handle_refs().map(|refs| refs.contains(id)).unwrap_or(false))
    }

    fn key_handle_refs(&self) -> Result<BTreeSet<String>> {
        Ok(self
            .store
            .keys()?
            .into_iter()
            .filter_map(|k| match k.storage {
                KeyStorage::SecurityKey { key_handle } => Some(key_handle.0),
                _ => None,
            })
            .collect())
    }

    /// Everything local that syncs, as `collection/id` → JSON object.
    fn local_snapshot(&self) -> Result<BTreeMap<String, serde_json::Value>> {
        let mut out = BTreeMap::new();
        for table in SYNCED_TABLES {
            for (id, value) in self.store.raw_records(table)? {
                // Secure Enclave keys are bound to this device's hardware.
                if *table == "keys" && value.pointer("/storage/type") == Some(&"secure_enclave".into()) {
                    continue;
                }
                out.insert(entry_key(table, &id), value);
            }
        }
        for (host, port, key) in self.store.all_known_host_keys()? {
            out.insert(
                entry_key(KNOWN_HOSTS, &known_host_id(&host, port, &key.algorithm)),
                serde_json::json!({
                    "host": host, "port": port, "algorithm": key.algorithm,
                    "public_key": key.public_key, "fingerprint": key.fingerprint,
                }),
            );
        }
        for secret in self.synced_secret_refs()? {
            if let Some(value) = self.secrets.get(&secret)? {
                let encoded = base64::engine::general_purpose::STANDARD.encode(value);
                out.insert(entry_key(SECRETS, &secret.0), serde_json::json!({ "value": encoded }));
            }
        }
        Ok(out)
    }

    /// Secret refs used by synced records that this device shares.
    fn synced_secret_refs(&self) -> Result<Vec<SecretRef>> {
        let mut refs = Vec::new();
        for key in self.store.keys()? {
            match key.storage {
                KeyStorage::SecurityKey { key_handle } => refs.push(key_handle),
                KeyStorage::Software { secret, passphrase } if self.include_secrets => {
                    refs.push(secret);
                    refs.extend(passphrase);
                }
                _ => {}
            }
        }
        if self.include_secrets {
            for host in self.store.hosts()? {
                if let AuthMethod::Password { secret: Some(secret) } = host.auth {
                    refs.push(secret);
                }
            }
        }
        Ok(refs)
    }

    /// Writes changed records to the database and secret store. Returns how many changed.
    fn apply(&self, before: &SyncState, after: &SyncState) -> Result<usize> {
        let mut changed = 0;
        let differs = |key: &str| before.entries.get(key) != after.entries.get(key);
        let allowed_secrets: BTreeSet<String> = if self.include_secrets {
            after.live(SECRETS).into_iter().map(|(id, _)| id).collect()
        } else {
            // Only key handles of synced FIDO2 keys.
            after
                .live("keys")
                .into_iter()
                .filter_map(|(_, v)| serde_json::from_value::<Key>(v).ok())
                .filter_map(|k| match k.storage {
                    KeyStorage::SecurityKey { key_handle } => Some(key_handle.0),
                    _ => None,
                })
                .collect()
        };

        // Secrets first, so records referencing them are usable immediately.
        for (key, entry) in &after.entries {
            let Some(id) = key.strip_prefix(&format!("{SECRETS}/")) else { continue };
            if !differs(key) || !allowed_secrets.contains(id) && entry.is_live() {
                continue;
            }
            let secret = SecretRef(id.to_string());
            if entry.is_live() {
                let encoded = entry.value()["value"].as_str().unwrap_or_default().to_string();
                if let Ok(value) = base64::engine::general_purpose::STANDARD.decode(encoded) {
                    self.secrets.set(&secret, &value)?;
                    changed += 1;
                }
            } else if self.include_secrets {
                self.secrets.delete(&secret)?;
                changed += 1;
            }
        }

        for table in SYNCED_TABLES {
            let prefix = format!("{table}/");
            for (key, entry) in &after.entries {
                let Some(id) = key.strip_prefix(&prefix) else { continue };
                if !differs(key) {
                    continue;
                }
                if entry.is_live() {
                    // Records from newer app versions may not parse yet; keep them in the state.
                    if self.store.put_raw_record(table, &entry.value()).is_ok() {
                        changed += 1;
                    }
                } else {
                    self.store.delete_raw_record(table, id)?;
                    changed += 1;
                }
            }
        }

        for (key, entry) in &after.entries {
            if !key.starts_with(&format!("{KNOWN_HOSTS}/")) || !differs(key) {
                continue;
            }
            let v = entry.value();
            let (Some(host), Some(port), Some(algorithm)) =
                (v["host"].as_str(), v["port"].as_u64(), v["algorithm"].as_str())
            else {
                continue;
            };
            if entry.is_live() {
                let record = KnownHostKey {
                    algorithm: algorithm.into(),
                    public_key: v["public_key"].as_str().unwrap_or_default().into(),
                    fingerprint: v["fingerprint"].as_str().unwrap_or_default().into(),
                };
                self.store.trust_host_key(host, port as u16, &record)?;
            } else {
                self.store.forget_host_key(host, port as u16, algorithm)?;
            }
            changed += 1;
        }
        Ok(changed)
    }
}

fn known_host_id(host: &str, port: u16, algorithm: &str) -> String {
    format!("{host}:{port}:{algorithm}")
}
