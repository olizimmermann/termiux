//! Local persistence (SQLite) for hosts, groups, keys and known host keys.
//!
//! Records are stored as JSON next to a few indexed columns, so adding model fields needs
//! no migration. Secrets never touch this database; see [`SecretStore`].

mod secrets;

use std::path::Path;
use std::sync::Mutex;

use rusqlite::{Connection, OptionalExtension, params};
use serde::Serialize;
use serde::de::DeserializeOwned;
use termiux_model::{Group, Host, HostKeyStatus, Key, now};
use uuid::Uuid;

pub use secrets::{MemorySecretStore, SecretError, SecretStore};

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("database: {0}")]
    Sql(#[from] rusqlite::Error),
    #[error("corrupt record: {0}")]
    Json(#[from] serde_json::Error),
    #[error("database schema {0} is newer than this app supports")]
    SchemaTooNew(i64),
}

type Result<T> = std::result::Result<T, StoreError>;

/// Ordered schema migrations; index + 1 is the resulting `user_version`.
const MIGRATIONS: &[&str] = &[
    // 1: initial schema
    "CREATE TABLE hosts (id TEXT PRIMARY KEY, label TEXT NOT NULL, data TEXT NOT NULL, updated_at INTEGER NOT NULL);
     CREATE TABLE groups (id TEXT PRIMARY KEY, label TEXT NOT NULL, data TEXT NOT NULL, updated_at INTEGER NOT NULL);
     CREATE TABLE keys (id TEXT PRIMARY KEY, label TEXT NOT NULL, data TEXT NOT NULL, updated_at INTEGER NOT NULL);
     CREATE TABLE known_hosts (
         host TEXT NOT NULL,
         port INTEGER NOT NULL,
         algorithm TEXT NOT NULL,
         public_key TEXT NOT NULL,
         fingerprint TEXT NOT NULL,
         added_at INTEGER NOT NULL,
         PRIMARY KEY (host, port, algorithm)
     );",
];

/// A record kind stored in its own table as JSON.
trait Record: Serialize + DeserializeOwned {
    const TABLE: &'static str;
    fn id(&self) -> Uuid;
    fn label(&self) -> &str;
    fn updated_at(&self) -> i64;
}

macro_rules! record {
    ($ty:ty, $table:literal, $label:ident) => {
        impl Record for $ty {
            const TABLE: &'static str = $table;
            fn id(&self) -> Uuid {
                self.id
            }
            fn label(&self) -> &str {
                &self.$label
            }
            fn updated_at(&self) -> i64 {
                self.updated_at
            }
        }
    };
}

record!(Host, "hosts", label);
record!(Group, "groups", name);
record!(Key, "keys", label);

/// A host key as recorded in known_hosts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnownHostKey {
    pub algorithm: String,
    /// Base64 key blob as in an OpenSSH public key line.
    pub public_key: String,
    pub fingerprint: String,
}

pub struct Store {
    conn: Mutex<Connection>,
}

impl Store {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        Self::init(Connection::open(path)?)
    }

    pub fn open_in_memory() -> Result<Self> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(mut conn: Connection) -> Result<Self> {
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        let version: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
        if version > MIGRATIONS.len() as i64 {
            return Err(StoreError::SchemaTooNew(version));
        }
        for (i, sql) in MIGRATIONS.iter().enumerate().skip(version as usize) {
            let tx = conn.transaction()?;
            tx.execute_batch(sql)?;
            tx.pragma_update(None, "user_version", i as i64 + 1)?;
            tx.commit()?;
        }
        Ok(Self { conn: Mutex::new(conn) })
    }

    fn conn(&self) -> std::sync::MutexGuard<'_, Connection> {
        // A panic while holding the lock cannot leave SQLite in a torn state, so recover.
        self.conn.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn put<R: Record>(&self, record: &R) -> Result<()> {
        let sql = format!(
            "INSERT INTO {} (id, label, data, updated_at) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(id) DO UPDATE SET label = ?2, data = ?3, updated_at = ?4",
            R::TABLE
        );
        self.conn().execute(
            &sql,
            params![record.id().to_string(), record.label(), serde_json::to_string(record)?, record.updated_at()],
        )?;
        Ok(())
    }

    fn get<R: Record>(&self, id: Uuid) -> Result<Option<R>> {
        let sql = format!("SELECT data FROM {} WHERE id = ?1", R::TABLE);
        let data: Option<String> = self.conn().query_row(&sql, [id.to_string()], |r| r.get(0)).optional()?;
        Ok(data.map(|d| serde_json::from_str(&d)).transpose()?)
    }

    fn list<R: Record>(&self) -> Result<Vec<R>> {
        let sql = format!("SELECT data FROM {} ORDER BY label COLLATE NOCASE", R::TABLE);
        let conn = self.conn();
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
        rows.map(|d| Ok(serde_json::from_str(&d?)?)).collect()
    }

    fn delete<R: Record>(&self, id: Uuid) -> Result<bool> {
        let sql = format!("DELETE FROM {} WHERE id = ?1", R::TABLE);
        Ok(self.conn().execute(&sql, [id.to_string()])? > 0)
    }

    pub fn save_host(&self, host: &Host) -> Result<()> {
        self.put(host)
    }
    pub fn host(&self, id: Uuid) -> Result<Option<Host>> {
        self.get(id)
    }
    pub fn hosts(&self) -> Result<Vec<Host>> {
        self.list()
    }
    pub fn delete_host(&self, id: Uuid) -> Result<bool> {
        self.delete::<Host>(id)
    }

    pub fn save_group(&self, group: &Group) -> Result<()> {
        self.put(group)
    }
    pub fn groups(&self) -> Result<Vec<Group>> {
        self.list()
    }
    pub fn delete_group(&self, id: Uuid) -> Result<bool> {
        self.delete::<Group>(id)
    }

    pub fn save_key(&self, key: &Key) -> Result<()> {
        self.put(key)
    }
    pub fn key(&self, id: Uuid) -> Result<Option<Key>> {
        self.get(id)
    }
    pub fn keys(&self) -> Result<Vec<Key>> {
        self.list()
    }
    pub fn delete_key(&self, id: Uuid) -> Result<bool> {
        self.delete::<Key>(id)
    }

    /// Checks a presented server key against known_hosts. Any recorded key for the same
    /// host:port that does not match counts as changed, regardless of algorithm, so a
    /// server (or attacker) cannot dodge the warning by offering a different key type.
    pub fn check_host_key(&self, host: &str, port: u16, key: &KnownHostKey) -> Result<HostKeyStatus> {
        let known = self.known_host_keys(host, port)?;
        if known.is_empty() {
            return Ok(HostKeyStatus::Unknown);
        }
        if known.iter().any(|k| k.algorithm == key.algorithm && k.public_key == key.public_key) {
            return Ok(HostKeyStatus::Trusted);
        }
        let previous = known.iter().find(|k| k.algorithm == key.algorithm).unwrap_or(&known[0]);
        Ok(HostKeyStatus::Changed { previous_fingerprint: previous.fingerprint.clone() })
    }

    pub fn known_host_keys(&self, host: &str, port: u16) -> Result<Vec<KnownHostKey>> {
        let conn = self.conn();
        let mut stmt =
            conn.prepare("SELECT algorithm, public_key, fingerprint FROM known_hosts WHERE host = ?1 AND port = ?2")?;
        let rows = stmt.query_map(params![host, port], |r| {
            Ok(KnownHostKey { algorithm: r.get(0)?, public_key: r.get(1)?, fingerprint: r.get(2)? })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Records a trusted key, replacing any previous key of the same algorithm.
    pub fn trust_host_key(&self, host: &str, port: u16, key: &KnownHostKey) -> Result<()> {
        self.conn().execute(
            "INSERT OR REPLACE INTO known_hosts (host, port, algorithm, public_key, fingerprint, added_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![host, port, key.algorithm, key.public_key, key.fingerprint, now()],
        )?;
        Ok(())
    }

    /// Forgets every key for host:port (used after the user accepts a legitimate key change).
    pub fn forget_host(&self, host: &str, port: u16) -> Result<()> {
        self.conn().execute("DELETE FROM known_hosts WHERE host = ?1 AND port = ?2", params![host, port])?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use termiux_model::{AuthMethod, SecretRef};

    fn key(alg: &str, blob: &str) -> KnownHostKey {
        KnownHostKey { algorithm: alg.into(), public_key: blob.into(), fingerprint: format!("SHA256:{blob}") }
    }

    #[test]
    fn host_round_trip_and_upsert() {
        let store = Store::open_in_memory().unwrap();
        let mut host = Host::new("web", "example.com", "root");
        host.auth = AuthMethod::Password { secret: Some(SecretRef::new()) };
        host.tags = vec!["prod".into()];
        store.save_host(&host).unwrap();
        assert_eq!(store.host(host.id).unwrap().as_ref(), Some(&host));

        host.label = "web-1".into();
        host.port = 2200;
        store.save_host(&host).unwrap();
        let hosts = store.hosts().unwrap();
        assert_eq!(hosts, vec![host.clone()]);

        assert!(store.delete_host(host.id).unwrap());
        assert!(store.hosts().unwrap().is_empty());
    }

    #[test]
    fn hosts_sorted_by_label() {
        let store = Store::open_in_memory().unwrap();
        for label in ["zeta", "Alpha", "beta"] {
            store.save_host(&Host::new(label, "h", "u")).unwrap();
        }
        let labels: Vec<_> = store.hosts().unwrap().into_iter().map(|h| h.label).collect();
        assert_eq!(labels, ["Alpha", "beta", "zeta"]);
    }

    #[test]
    fn known_hosts_tofu_and_change_detection() {
        let store = Store::open_in_memory().unwrap();
        let ed = key("ssh-ed25519", "AAA");
        assert_eq!(store.check_host_key("h", 22, &ed).unwrap(), HostKeyStatus::Unknown);

        store.trust_host_key("h", 22, &ed).unwrap();
        assert_eq!(store.check_host_key("h", 22, &ed).unwrap(), HostKeyStatus::Trusted);
        // Same host, other port is a different identity.
        assert_eq!(store.check_host_key("h", 2222, &ed).unwrap(), HostKeyStatus::Unknown);

        let swapped = key("ssh-ed25519", "BBB");
        assert_eq!(
            store.check_host_key("h", 22, &swapped).unwrap(),
            HostKeyStatus::Changed { previous_fingerprint: "SHA256:AAA".into() }
        );
        // Offering a different algorithm must not bypass the warning.
        let rsa = key("rsa-sha2-512", "CCC");
        assert!(matches!(store.check_host_key("h", 22, &rsa).unwrap(), HostKeyStatus::Changed { .. }));

        store.forget_host("h", 22).unwrap();
        assert_eq!(store.check_host_key("h", 22, &swapped).unwrap(), HostKeyStatus::Unknown);
    }

    #[test]
    fn reopen_keeps_data_and_schema() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("termiux.db");
        let host = Host::new("a", "b", "c");
        Store::open(&path).unwrap().save_host(&host).unwrap();
        let store = Store::open(&path).unwrap();
        assert_eq!(store.hosts().unwrap(), vec![host]);
    }
}
