//! Two simulated devices (own database + secret store) syncing through a shared folder.

use termiux_model::{AuthMethod, Host, Key, KeyStorage, SecretRef, now};
use termiux_store::{KnownHostKey, MemorySecretStore, SecretStore, Store};
use termiux_sync::{FolderTransport, SyncEngine, SyncReport, VaultKey};

struct Device {
    store: Store,
    secrets: MemorySecretStore,
    include_secrets: bool,
}

impl Device {
    fn new() -> Self {
        Self { store: Store::open_in_memory().unwrap(), secrets: MemorySecretStore::default(), include_secrets: false }
    }

    fn sync(&self, key: &VaultKey, folder: &std::path::Path) -> SyncReport {
        let engine =
            SyncEngine { store: &self.store, secrets: &self.secrets, key, include_secrets: self.include_secrets };
        engine.sync(&FolderTransport { dir: folder.to_path_buf() }).unwrap()
    }
}

fn setup() -> (Device, Device, VaultKey, tempfile::TempDir) {
    (Device::new(), Device::new(), VaultKey::generate().unwrap(), tempfile::tempdir().unwrap())
}

#[test]
fn hosts_propagate_and_concurrent_edits_merge() {
    let (a, b, key, dir) = setup();
    let mut host = Host::new("web", "web.example.com", "root");
    a.store.save_host(&host).unwrap();

    a.sync(&key, dir.path());
    let report = b.sync(&key, dir.path());
    assert_eq!(report.received, 1);
    assert_eq!(report.devices, 1);
    assert_eq!(b.store.host(host.id).unwrap().unwrap().hostname, "web.example.com");

    // Concurrent edits to different fields on both devices.
    host.label = "web (prod)".into();
    a.store.save_host(&host).unwrap();
    let mut on_b = b.store.host(host.id).unwrap().unwrap();
    on_b.port = 2222;
    b.store.save_host(&on_b).unwrap();

    a.sync(&key, dir.path());
    b.sync(&key, dir.path());
    a.sync(&key, dir.path());
    let (ha, hb) = (a.store.host(host.id).unwrap().unwrap(), b.store.host(host.id).unwrap().unwrap());
    assert_eq!(ha.label, "web (prod)");
    assert_eq!(ha.port, 2222);
    assert_eq!(ha, hb, "both devices converge");

    // A further round with no changes is quiet.
    let quiet = a.sync(&key, dir.path());
    assert_eq!((quiet.sent, quiet.received), (0, 0));
}

#[test]
fn deletions_propagate() {
    let (a, b, key, dir) = setup();
    let host = Host::new("old", "old.example.com", "root");
    a.store.save_host(&host).unwrap();
    a.sync(&key, dir.path());
    b.sync(&key, dir.path());

    b.store.delete_host(host.id).unwrap();
    b.sync(&key, dir.path());
    a.sync(&key, dir.path());
    assert!(a.store.host(host.id).unwrap().is_none());
}

#[test]
fn passwords_sync_only_when_enabled() {
    let (mut a, mut b, key, dir) = setup();
    let secret = SecretRef::new();
    a.secrets.set(&secret, b"hunter2").unwrap();
    let mut host = Host::new("db", "db.example.com", "admin");
    host.auth = AuthMethod::Password { secret: Some(secret.clone()) };
    a.store.save_host(&host).unwrap();

    a.sync(&key, dir.path());
    b.sync(&key, dir.path());
    assert!(b.store.host(host.id).unwrap().is_some(), "the host itself syncs");
    assert!(b.secrets.get(&secret).unwrap().is_none(), "the password does not");

    a.include_secrets = true;
    b.include_secrets = true;
    a.sync(&key, dir.path());
    b.sync(&key, dir.path());
    assert_eq!(b.secrets.get(&secret).unwrap().as_deref(), Some(b"hunter2".as_slice()));

    // The folder only holds ciphertext.
    for file in std::fs::read_dir(dir.path()).unwrap() {
        let bytes = std::fs::read(file.unwrap().path()).unwrap();
        assert!(!bytes.windows(7).any(|w| w == b"hunter2" || w == b"db.exam"));
    }
}

fn key_record(label: &str, storage: KeyStorage) -> Key {
    Key {
        id: uuid::Uuid::new_v4(),
        label: label.into(),
        public_key: "ssh-ed25519 AAAA test".into(),
        storage,
        updated_at: now(),
    }
}

#[test]
fn security_key_handles_always_sync_secure_enclave_never() {
    let (a, b, key, dir) = setup();
    let handle = SecretRef::new();
    a.secrets.set(&handle, b"sk key handle file").unwrap();
    let yubikey = key_record("yubikey", KeyStorage::SecurityKey { key_handle: handle.clone() });
    let enclave = key_record("touch id", KeyStorage::SecureEnclave { tag: "t".into() });
    let software = SecretRef::new();
    a.secrets.set(&software, b"PRIVATE").unwrap();
    let laptop = key_record("laptop", KeyStorage::Software { secret: software.clone(), passphrase: None });
    for k in [&yubikey, &enclave, &laptop] {
        a.store.save_key(k).unwrap();
    }

    a.sync(&key, dir.path());
    b.sync(&key, dir.path());
    let labels: Vec<_> = b.store.keys().unwrap().into_iter().map(|k| k.label).collect();
    assert_eq!(labels, ["laptop", "yubikey"]);
    assert_eq!(b.secrets.get(&handle).unwrap().as_deref(), Some(b"sk key handle file".as_slice()));
    assert!(b.secrets.get(&software).unwrap().is_none(), "private key needs secret sync enabled");
}

#[test]
fn known_hosts_sync() {
    let (a, b, key, dir) = setup();
    let record =
        KnownHostKey { algorithm: "ssh-ed25519".into(), public_key: "AAAA".into(), fingerprint: "SHA256:x".into() };
    a.store.trust_host_key("srv", 22, &record).unwrap();
    a.sync(&key, dir.path());
    b.sync(&key, dir.path());
    assert_eq!(b.store.known_host_keys("srv", 22).unwrap(), vec![record]);
}

#[test]
fn files_from_another_vault_are_ignored() {
    let (a, b, key, dir) = setup();
    let other_vault = VaultKey::generate().unwrap();
    let stranger = Device::new();
    stranger.store.save_host(&Host::new("stranger", "x", "y")).unwrap();
    stranger.sync(&other_vault, dir.path());

    a.store.save_host(&Host::new("mine", "m", "u")).unwrap();
    a.sync(&key, dir.path());
    let report = b.sync(&key, dir.path());
    assert_eq!(report.devices, 1);
    let names: Vec<_> = b.store.hosts().unwrap().into_iter().map(|h| h.label).collect();
    assert_eq!(names, ["mine"]);
}
