//! UniFFI surface consumed by the Swift (and later Kotlin) apps. Thin adapters only:
//! behaviour lives in termiux-session and below.

use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

use termiux_model as model;
use termiux_session::{Core, SessionError};
use termiux_ssh::{HostKeyError, SshError};
use termiux_store::Store;
use uuid::Uuid;

uniffi::setup_scaffolding!();

// MARK: errors

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum CoreError {
    #[error("The host key for {host} has changed")]
    HostKeyChanged { host: String, port: u16, fingerprint: String, previous_fingerprint: String },
    #[error("Host key for {host} was not trusted")]
    HostKeyNotTrusted { host: String },
    #[error("Authentication failed")]
    AuthRejected,
    #[error("Cancelled")]
    Cancelled,
    #[error("{message}")]
    InvalidKey { message: String },
    #[error("{message}")]
    InvalidTheme { message: String },
    #[error("{message}")]
    Unsupported { message: String },
    #[error("{message}")]
    Failed { message: String },
}

fn failed(e: impl std::fmt::Display) -> CoreError {
    CoreError::Failed { message: e.to_string() }
}

impl CoreError {
    fn from_session(e: SessionError, port: u16) -> Self {
        match e {
            SessionError::Ssh(SshError::AuthRejected) => CoreError::AuthRejected,
            SessionError::Ssh(SshError::HostKey(HostKeyError::Changed { host, fingerprint, previous_fingerprint })) => {
                CoreError::HostKeyChanged { host, port, fingerprint, previous_fingerprint }
            }
            SessionError::Ssh(SshError::HostKey(HostKeyError::NotTrusted { host, .. })) => {
                CoreError::HostKeyNotTrusted { host }
            }
            SessionError::Cancelled => CoreError::Cancelled,
            SessionError::InvalidKey(message) => CoreError::InvalidKey { message },
            SessionError::Unsupported(what) => {
                CoreError::Unsupported { message: format!("{what} are not supported yet") }
            }
            other => failed(other),
        }
    }
}

impl From<SessionError> for CoreError {
    fn from(e: SessionError) -> Self {
        CoreError::from_session(e, 0)
    }
}

impl From<termiux_store::StoreError> for CoreError {
    fn from(e: termiux_store::StoreError) -> Self {
        failed(e)
    }
}

fn parse_id(id: &str) -> Result<Uuid, CoreError> {
    Uuid::parse_str(id).map_err(|_| failed(format!("invalid id {id}")))
}

// MARK: foreign traits

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum SecretStoreError {
    #[error("{message}")]
    Failed { message: String },
}

impl From<uniffi::UnexpectedUniFFICallbackError> for SecretStoreError {
    fn from(e: uniffi::UnexpectedUniFFICallbackError) -> Self {
        SecretStoreError::Failed { message: e.reason }
    }
}

/// Platform secure storage (Keychain on Apple). Keys are opaque ids.
#[uniffi::export(with_foreign)]
pub trait SecretStore: Send + Sync {
    fn get(&self, id: String) -> Result<Option<Vec<u8>>, SecretStoreError>;
    fn set(&self, id: String, value: Vec<u8>) -> Result<(), SecretStoreError>;
    fn delete(&self, id: String) -> Result<(), SecretStoreError>;
}

struct SecretStoreAdapter(Arc<dyn SecretStore>);

impl termiux_store::SecretStore for SecretStoreAdapter {
    fn get(&self, s: &model::SecretRef) -> Result<Option<Vec<u8>>, termiux_store::SecretError> {
        self.0.get(s.0.clone()).map_err(|e| termiux_store::SecretError::Unavailable(e.to_string()))
    }
    fn set(&self, s: &model::SecretRef, value: &[u8]) -> Result<(), termiux_store::SecretError> {
        self.0.set(s.0.clone(), value.to_vec()).map_err(|e| termiux_store::SecretError::Unavailable(e.to_string()))
    }
    fn delete(&self, s: &model::SecretRef) -> Result<(), termiux_store::SecretError> {
        self.0.delete(s.0.clone()).map_err(|e| termiux_store::SecretError::Unavailable(e.to_string()))
    }
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct HostKeyInfo {
    pub host: String,
    pub port: u16,
    pub algorithm: String,
    pub fingerprint: String,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct InteractivePrompt {
    pub text: String,
    pub echo: bool,
}

/// User interaction during connect. Called on core threads; implementations may block
/// (e.g. show a modal on the main thread and wait).
#[uniffi::export(with_foreign)]
pub trait Interaction: Send + Sync {
    fn confirm_new_host(&self, info: HostKeyInfo) -> bool;
    fn keyboard_interactive(
        &self,
        name: String,
        instructions: String,
        prompts: Vec<InteractivePrompt>,
    ) -> Option<Vec<String>>;
    fn ask_secret(&self, title: String, message: String) -> Option<String>;
    fn status(&self, message: String);
}

struct InteractionAdapter(Arc<dyn Interaction>);

impl termiux_session::Interaction for InteractionAdapter {
    fn confirm_new_host(&self, info: &termiux_ssh::HostKeyInfo) -> bool {
        self.0.confirm_new_host(HostKeyInfo {
            host: info.host.clone(),
            port: info.port,
            algorithm: info.algorithm.clone(),
            fingerprint: info.fingerprint.clone(),
        })
    }
    fn keyboard_interactive(&self, name: &str, instructions: &str, prompts: &[(String, bool)]) -> Option<Vec<String>> {
        let prompts =
            prompts.iter().map(|(text, echo)| InteractivePrompt { text: text.clone(), echo: *echo }).collect();
        self.0.keyboard_interactive(name.to_string(), instructions.to_string(), prompts)
    }
    fn ask_secret(&self, title: &str, message: &str) -> Option<String> {
        self.0.ask_secret(title.to_string(), message.to_string())
    }
    fn status(&self, message: &str) {
        self.0.status(message.to_string())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum EndReason {
    Exited,
    ConnectionLost,
    UserClosed,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct SessionEnd {
    pub exit_status: Option<u32>,
    pub reason: EndReason,
}

/// Receives terminal output and the end of the session. Called on core threads.
#[uniffi::export(with_foreign)]
pub trait TerminalListener: Send + Sync {
    fn on_output(&self, data: Vec<u8>);
    fn on_end(&self, end: SessionEnd);
}

struct SinkAdapter(Arc<dyn TerminalListener>);

impl termiux_session::TerminalSink for SinkAdapter {
    fn output(&self, data: &[u8]) {
        self.0.on_output(data.to_vec())
    }
    fn ended(&self, end: model::SessionEnd) {
        let reason = match end.reason {
            model::EndReason::Exited => EndReason::Exited,
            model::EndReason::ConnectionLost => EndReason::ConnectionLost,
            model::EndReason::UserClosed => EndReason::UserClosed,
        };
        self.0.on_end(SessionEnd { exit_status: end.exit_status, reason })
    }
}

// MARK: records

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum HostAuth {
    /// `saved` tells whether a password is stored; the value itself never crosses FFI.
    Password {
        saved: bool,
    },
    Key {
        key_id: String,
    },
    KeyboardInteractive,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct HostRecord {
    /// Empty for a new host.
    pub id: String,
    pub label: String,
    pub group_id: Option<String>,
    pub hostname: String,
    pub port: u16,
    pub username: String,
    pub auth: HostAuth,
    pub keepalive_secs: u32,
    pub term: String,
    pub startup_command: Option<String>,
    /// `None` uses the app's default theme.
    pub theme_id: Option<String>,
}

impl From<&model::Host> for HostRecord {
    fn from(h: &model::Host) -> Self {
        let auth = match &h.auth {
            model::AuthMethod::Password { secret } => HostAuth::Password { saved: secret.is_some() },
            model::AuthMethod::Key { key_id } => HostAuth::Key { key_id: key_id.to_string() },
            model::AuthMethod::KeyboardInteractive | model::AuthMethod::Agent => HostAuth::KeyboardInteractive,
        };
        Self {
            id: h.id.to_string(),
            label: h.label.clone(),
            group_id: h.group_id.map(|g| g.to_string()),
            hostname: h.hostname.clone(),
            port: h.port,
            username: h.username.clone(),
            auth,
            keepalive_secs: h.keepalive_secs,
            term: h.term.clone(),
            startup_command: h.startup_command.clone(),
            theme_id: h.theme_id.map(|t| t.to_string()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ThemeRecord {
    pub id: String,
    pub name: String,
    pub foreground: String,
    pub background: String,
    pub cursor: String,
    pub cursor_text: Option<String>,
    pub selection_background: String,
    pub selection_foreground: Option<String>,
    /// 16 ANSI colours, `#rrggbb`.
    pub palette: Vec<String>,
    pub builtin: bool,
}

impl From<&model::Theme> for ThemeRecord {
    fn from(t: &model::Theme) -> Self {
        Self {
            id: t.id.to_string(),
            name: t.name.clone(),
            foreground: t.foreground.clone(),
            background: t.background.clone(),
            cursor: t.cursor.clone(),
            cursor_text: t.cursor_text.clone(),
            selection_background: t.selection_background.clone(),
            selection_foreground: t.selection_foreground.clone(),
            palette: t.palette.clone(),
            builtin: t.builtin,
        }
    }
}

/// Id of the theme used when neither the host nor the user picked one.
#[uniffi::export]
pub fn default_theme_id() -> String {
    termiux_theme::default_theme_id().to_string()
}

/// How to treat the stored password when saving a host.
#[derive(Debug, Clone, uniffi::Enum)]
pub enum PasswordChange {
    Keep,
    Set { password: String },
    Clear,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum KeyKind {
    Software,
    SecurityKey,
    Piv,
    SecureEnclave,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct KeyRecord {
    pub id: String,
    pub label: String,
    pub public_key: String,
    pub kind: KeyKind,
}

impl From<&model::Key> for KeyRecord {
    fn from(k: &model::Key) -> Self {
        let kind = match k.storage {
            model::KeyStorage::Software { .. } => KeyKind::Software,
            model::KeyStorage::SecurityKey { .. } => KeyKind::SecurityKey,
            model::KeyStorage::Piv { .. } => KeyKind::Piv,
            model::KeyStorage::SecureEnclave { .. } => KeyKind::SecureEnclave,
        };
        Self { id: k.id.to_string(), label: k.label.clone(), public_key: k.public_key.clone(), kind }
    }
}

// MARK: core

fn runtime() -> &'static tokio::runtime::Runtime {
    static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .thread_name("termiux-core")
            .build()
            .expect("tokio runtime")
    })
}

#[derive(uniffi::Object)]
pub struct TermiuxCore {
    core: Arc<Core>,
}

#[uniffi::export(async_runtime = "tokio")]
impl TermiuxCore {
    /// Opens (or creates) the database in `data_dir`.
    #[uniffi::constructor]
    pub fn open(data_dir: String, secrets: Arc<dyn SecretStore>) -> Result<Arc<Self>, CoreError> {
        let dir = PathBuf::from(data_dir);
        std::fs::create_dir_all(&dir).map_err(failed)?;
        let store = Store::open(dir.join("termiux.sqlite"))?;
        Ok(Arc::new(Self {
            core: Arc::new(Core { store: Arc::new(store), secrets: Arc::new(SecretStoreAdapter(secrets)) }),
        }))
    }

    pub fn hosts(&self) -> Result<Vec<HostRecord>, CoreError> {
        Ok(self.core.store.hosts()?.iter().map(HostRecord::from).collect())
    }

    /// Creates or updates a host and returns it as saved.
    pub fn save_host(&self, record: HostRecord, password: PasswordChange) -> Result<HostRecord, CoreError> {
        let existing = if record.id.is_empty() { None } else { self.core.store.host(parse_id(&record.id)?)? };
        let mut host = existing.clone().unwrap_or_else(|| model::Host::new("", "", ""));
        host.label = record.label;
        host.group_id = record.group_id.as_deref().map(parse_id).transpose()?;
        host.hostname = record.hostname;
        host.port = record.port;
        host.username = record.username;
        host.keepalive_secs = record.keepalive_secs;
        host.term = if record.term.is_empty() { "xterm-256color".into() } else { record.term };
        host.startup_command = record.startup_command.filter(|c| !c.trim().is_empty());
        host.theme_id = record.theme_id.as_deref().map(parse_id).transpose()?;
        host.updated_at = model::now();

        let old_secret = match &host.auth {
            model::AuthMethod::Password { secret } => secret.clone(),
            _ => None,
        };
        match record.auth {
            HostAuth::Password { .. } => {
                host.auth = model::AuthMethod::Password { secret: old_secret.clone() };
                match password {
                    PasswordChange::Keep => self.core.store.save_host(&host)?,
                    PasswordChange::Set { password } => self.core.set_host_password(&mut host, Some(&password))?,
                    PasswordChange::Clear => self.core.set_host_password(&mut host, None)?,
                }
            }
            other => {
                // Switching away from password auth: drop the stored password.
                if let Some(secret) = old_secret {
                    self.core.secrets.delete(&secret).map_err(failed)?;
                }
                host.auth = match other {
                    HostAuth::Key { key_id } => model::AuthMethod::Key { key_id: parse_id(&key_id)? },
                    _ => model::AuthMethod::KeyboardInteractive,
                };
                self.core.store.save_host(&host)?;
            }
        }
        Ok(HostRecord::from(&host))
    }

    pub fn delete_host(&self, id: String) -> Result<(), CoreError> {
        let id = parse_id(&id)?;
        if let Some(mut host) = self.core.store.host(id)? {
            if matches!(host.auth, model::AuthMethod::Password { secret: Some(_) }) {
                self.core.set_host_password(&mut host, None)?;
            }
            self.core.store.delete_host(id)?;
        }
        Ok(())
    }

    pub fn keys(&self) -> Result<Vec<KeyRecord>, CoreError> {
        Ok(self.core.store.keys()?.iter().map(KeyRecord::from).collect())
    }

    /// Imports an OpenSSH private key file (software or FIDO2 `sk-` key).
    pub fn import_key(
        &self,
        label: String,
        contents: String,
        passphrase: Option<String>,
    ) -> Result<KeyRecord, CoreError> {
        let key = self.core.import_key(&label, &contents, passphrase.as_deref().filter(|p| !p.is_empty()))?;
        Ok(KeyRecord::from(&key))
    }

    pub fn delete_key(&self, id: String) -> Result<(), CoreError> {
        Ok(self.core.delete_key(parse_id(&id)?)?)
    }

    /// Built-in themes followed by the user's own, each group sorted by name.
    pub fn themes(&self) -> Result<Vec<ThemeRecord>, CoreError> {
        let builtin = termiux_theme::builtin_themes();
        let user = self.core.store.themes()?;
        Ok(builtin.iter().chain(user.iter()).map(ThemeRecord::from).collect())
    }

    /// Imports an iTerm2 `.itermcolors` or Ghostty theme file.
    pub fn import_theme(&self, name: String, contents: Vec<u8>) -> Result<ThemeRecord, CoreError> {
        let theme =
            termiux_theme::import(&name, &contents).map_err(|e| CoreError::InvalidTheme { message: e.to_string() })?;
        self.core.store.save_theme(&theme)?;
        Ok(ThemeRecord::from(&theme))
    }

    /// Deletes a user theme. Hosts using it fall back to the default theme.
    pub fn delete_theme(&self, id: String) -> Result<(), CoreError> {
        let id = parse_id(&id)?;
        self.core.store.delete_theme(id)?;
        for mut host in self.core.store.hosts()?.into_iter().filter(|h| h.theme_id == Some(id)) {
            host.theme_id = None;
            host.updated_at = model::now();
            self.core.store.save_host(&host)?;
        }
        Ok(())
    }

    /// Forgets the recorded host key, e.g. after the user confirmed a legitimate change.
    pub fn forget_host_key(&self, host: String, port: u16) -> Result<(), CoreError> {
        Ok(self.core.store.forget_host(&host, port)?)
    }

    pub async fn connect(
        &self,
        host_id: String,
        cols: u32,
        rows: u32,
        ui: Arc<dyn Interaction>,
        listener: Arc<dyn TerminalListener>,
    ) -> Result<Arc<TerminalSession>, CoreError> {
        let host = self.core.store.host(parse_id(&host_id)?)?.ok_or_else(|| failed("host not found"))?;
        let core = self.core.clone();
        let port = host.port;
        // Run on our own runtime so sessions outlive whichever executor polled this future.
        runtime()
            .spawn(async move {
                let ui: Arc<dyn termiux_session::Interaction> = Arc::new(InteractionAdapter(ui));
                core.connect(host, cols, rows, ui, Arc::new(SinkAdapter(listener)))
                    .await
                    .map(|inner| Arc::new(TerminalSession { inner }))
                    .map_err(|e| CoreError::from_session(e, port))
            })
            .await
            .map_err(failed)?
    }

    /// Starts the user's login shell. Not available in sandboxed builds.
    pub fn open_local_shell(
        &self,
        cols: u32,
        rows: u32,
        listener: Arc<dyn TerminalListener>,
    ) -> Result<Arc<TerminalSession>, CoreError> {
        let clamp = |v: u32| v.min(u16::MAX as u32) as u16;
        let options = termiux_pty::ShellOptions { cols: clamp(cols), rows: clamp(rows), ..Default::default() };
        let inner = self.core.open_local_shell(options, Arc::new(SinkAdapter(listener)))?;
        Ok(Arc::new(TerminalSession { inner }))
    }
}

#[derive(uniffi::Object)]
pub struct TerminalSession {
    inner: termiux_session::TerminalSession,
}

#[uniffi::export(async_runtime = "tokio")]
impl TerminalSession {
    pub fn write(&self, data: Vec<u8>) {
        self.inner.write(&data);
    }

    pub fn resize(&self, cols: u32, rows: u32) {
        self.inner.resize(cols, rows);
    }

    pub async fn close(&self) {
        self.inner.close().await;
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Mutex;

    use super::*;

    #[derive(Default)]
    struct Secrets(Mutex<HashMap<String, Vec<u8>>>);

    impl SecretStore for Secrets {
        fn get(&self, id: String) -> Result<Option<Vec<u8>>, SecretStoreError> {
            Ok(self.0.lock().unwrap().get(&id).cloned())
        }
        fn set(&self, id: String, value: Vec<u8>) -> Result<(), SecretStoreError> {
            self.0.lock().unwrap().insert(id, value);
            Ok(())
        }
        fn delete(&self, id: String) -> Result<(), SecretStoreError> {
            self.0.lock().unwrap().remove(&id);
            Ok(())
        }
    }

    fn record(auth: HostAuth) -> HostRecord {
        HostRecord {
            id: String::new(),
            label: "web".into(),
            group_id: None,
            hostname: "example.com".into(),
            port: 22,
            username: "root".into(),
            auth,
            keepalive_secs: 30,
            term: String::new(),
            startup_command: Some("  ".into()),
            theme_id: None,
        }
    }

    #[test]
    fn save_host_manages_password_secret() {
        let dir = tempfile::tempdir().unwrap();
        let secrets = Arc::new(Secrets::default());
        let core = TermiuxCore::open(dir.path().to_string_lossy().into(), secrets.clone()).unwrap();

        let saved = core
            .save_host(record(HostAuth::Password { saved: false }), PasswordChange::Set { password: "pw".into() })
            .unwrap();
        assert!(!saved.id.is_empty());
        assert_eq!(saved.auth, HostAuth::Password { saved: true });
        assert_eq!(saved.term, "xterm-256color");
        assert_eq!(saved.startup_command, None);
        assert_eq!(secrets.0.lock().unwrap().len(), 1);

        // Editing other fields keeps the password.
        let mut edited = saved.clone();
        edited.port = 2222;
        let edited = core.save_host(edited, PasswordChange::Keep).unwrap();
        assert_eq!(edited.auth, HostAuth::Password { saved: true });
        assert_eq!(core.hosts().unwrap()[0].port, 2222);

        // Switching to keyboard-interactive removes the stored password.
        let mut kbd = edited.clone();
        kbd.auth = HostAuth::KeyboardInteractive;
        core.save_host(kbd, PasswordChange::Keep).unwrap();
        assert!(secrets.0.lock().unwrap().is_empty());

        core.delete_host(saved.id).unwrap();
        assert!(core.hosts().unwrap().is_empty());
    }
}
