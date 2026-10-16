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
    #[error("No security key found. Plug in your YubiKey and try again.")]
    NoSecurityKey,
    #[error("The security key needs its PIN")]
    PinRequired,
    #[error("Wrong PIN")]
    PinInvalid,
    #[error("{message}")]
    SecurityKey { message: String },
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
            SessionError::Fido(termiux_fido::FidoError::NoDevice) => CoreError::NoSecurityKey,
            SessionError::Fido(termiux_fido::FidoError::PinRequired) => CoreError::PinRequired,
            SessionError::Fido(termiux_fido::FidoError::PinInvalid) => CoreError::PinInvalid,
            SessionError::Fido(other) => CoreError::SecurityKey { message: other.to_string() },
            SessionError::Ssh(SshError::SecurityKey(e)) => CoreError::SecurityKey { message: e.to_string() },
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

/// Where a hardware-bound key lives.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum PlatformKeyRef {
    Piv { token_id: String, slot: String },
    SecureEnclave { tag: String },
}

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum PlatformSignError {
    #[error("{message}")]
    Failed { message: String },
}

impl From<uniffi::UnexpectedUniFFICallbackError> for PlatformSignError {
    fn from(e: uniffi::UnexpectedUniFFICallbackError) -> Self {
        PlatformSignError::Failed { message: e.reason }
    }
}

/// Signs with hardware keys (PIV via CryptoTokenKit, Secure Enclave). Returns X9.62 DER
/// for ECDSA and PKCS#1 v1.5 SHA-512 for RSA. Called on core threads; may block.
#[uniffi::export(with_foreign)]
pub trait PlatformKeys: Send + Sync {
    fn sign(&self, key: PlatformKeyRef, data: Vec<u8>) -> Result<Vec<u8>, PlatformSignError>;
}

struct PlatformAdapter(Arc<dyn PlatformKeys>);

impl termiux_session::PlatformSigner for PlatformAdapter {
    fn sign(&self, storage: &model::KeyStorage, data: &[u8]) -> Result<Vec<u8>, String> {
        let key = match storage {
            model::KeyStorage::Piv { token_id, slot } => {
                PlatformKeyRef::Piv { token_id: token_id.clone(), slot: slot.clone() }
            }
            model::KeyStorage::SecureEnclave { tag } => PlatformKeyRef::SecureEnclave { tag: tag.clone() },
            _ => return Err("not a platform key".into()),
        };
        self.0.sign(key, data.to_vec()).map_err(|e| e.to_string())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum KeyAlgorithm {
    Ed25519,
    EcdsaP256,
    EcdsaP384,
    Rsa3072,
    Rsa4096,
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
    /// Keys from the running ssh-agent (direct build only).
    Agent,
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
    /// Hosts to hop through, in order (ProxyJump).
    pub jump_host_ids: Vec<String>,
    pub forwards: Vec<PortForwardRecord>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum ForwardKind {
    /// -L: listen here, connect from the server.
    Local,
    /// -R: listen on the server, connect from here.
    Remote,
    /// -D: SOCKS5 proxy here.
    Dynamic,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct PortForwardRecord {
    /// Empty for a new forward.
    pub id: String,
    pub kind: ForwardKind,
    pub bind_host: String,
    pub bind_port: u16,
    pub target_host: String,
    pub target_port: u16,
    pub auto_start: bool,
}

impl From<&model::PortForward> for PortForwardRecord {
    fn from(f: &model::PortForward) -> Self {
        Self {
            id: f.id.to_string(),
            kind: match f.kind {
                model::ForwardKind::Local => ForwardKind::Local,
                model::ForwardKind::Remote => ForwardKind::Remote,
                model::ForwardKind::Dynamic => ForwardKind::Dynamic,
            },
            bind_host: f.bind_host.clone(),
            bind_port: f.bind_port,
            target_host: f.target_host.clone(),
            target_port: f.target_port,
            auto_start: f.auto_start,
        }
    }
}

impl PortForwardRecord {
    fn to_model(&self) -> Result<model::PortForward, CoreError> {
        Ok(model::PortForward {
            id: if self.id.is_empty() { Uuid::new_v4() } else { parse_id(&self.id)? },
            kind: match self.kind {
                ForwardKind::Local => model::ForwardKind::Local,
                ForwardKind::Remote => model::ForwardKind::Remote,
                ForwardKind::Dynamic => model::ForwardKind::Dynamic,
            },
            bind_host: if self.bind_host.is_empty() { "127.0.0.1".into() } else { self.bind_host.clone() },
            bind_port: self.bind_port,
            target_host: self.target_host.clone(),
            target_port: self.target_port,
            auto_start: self.auto_start,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ForwardStatus {
    pub forward: PortForwardRecord,
    pub running: bool,
    /// Actual listening address while running (useful when port 0 was requested).
    pub bound_host: Option<String>,
    pub bound_port: Option<u16>,
    pub error: Option<String>,
}

impl From<&model::Host> for HostRecord {
    fn from(h: &model::Host) -> Self {
        let auth = match &h.auth {
            model::AuthMethod::Password { secret } => HostAuth::Password { saved: secret.is_some() },
            model::AuthMethod::Key { key_id } => HostAuth::Key { key_id: key_id.to_string() },
            model::AuthMethod::KeyboardInteractive => HostAuth::KeyboardInteractive,
            model::AuthMethod::Agent => HostAuth::Agent,
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
            jump_host_ids: h.jump_hosts.iter().map(Uuid::to_string).collect(),
            forwards: h.forwards.iter().map(PortForwardRecord::from).collect(),
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

/// OpenSSH public key line from a platform public key: an uncompressed EC point
/// (`SecKeyCopyExternalRepresentation`, CryptoKit `x963Representation`) or PKCS#1 RSA DER.
#[uniffi::export]
pub fn openssh_public_key(raw: Vec<u8>, comment: String) -> Result<String, CoreError> {
    let result = if raw.first() == Some(&0x04) {
        termiux_keys::public_key_from_sec1(&raw, &comment)
    } else {
        termiux_keys::public_key_from_pkcs1(&raw, &comment)
    };
    result.map_err(|e| CoreError::InvalidKey { message: e.to_string() })
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
    /// Set for hardware-bound keys.
    pub platform: Option<PlatformKeyRef>,
}

impl From<&model::Key> for KeyRecord {
    fn from(k: &model::Key) -> Self {
        let kind = match k.storage {
            model::KeyStorage::Software { .. } => KeyKind::Software,
            model::KeyStorage::SecurityKey { .. } => KeyKind::SecurityKey,
            model::KeyStorage::Piv { .. } => KeyKind::Piv,
            model::KeyStorage::SecureEnclave { .. } => KeyKind::SecureEnclave,
        };
        let platform = match &k.storage {
            model::KeyStorage::Piv { token_id, slot } => {
                Some(PlatformKeyRef::Piv { token_id: token_id.clone(), slot: slot.clone() })
            }
            model::KeyStorage::SecureEnclave { tag } => Some(PlatformKeyRef::SecureEnclave { tag: tag.clone() }),
            _ => None,
        };
        Self { id: k.id.to_string(), label: k.label.clone(), public_key: k.public_key.clone(), kind, platform }
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
    pub fn open(
        data_dir: String,
        secrets: Arc<dyn SecretStore>,
        platform: Option<Arc<dyn PlatformKeys>>,
        agent_socket: Option<String>,
    ) -> Result<Arc<Self>, CoreError> {
        let dir = PathBuf::from(data_dir);
        std::fs::create_dir_all(&dir).map_err(failed)?;
        let store = Store::open(dir.join("termiux.sqlite"))?;
        Ok(Arc::new(Self {
            core: Arc::new(Core {
                store: Arc::new(store),
                secrets: Arc::new(SecretStoreAdapter(secrets)),
                platform: platform.map(|p| Arc::new(PlatformAdapter(p)) as Arc<dyn termiux_session::PlatformSigner>),
                agent_socket: agent_socket.filter(|s| !s.is_empty()).map(PathBuf::from),
            }),
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
        host.jump_hosts = record.jump_host_ids.iter().map(|id| parse_id(id)).collect::<Result<_, _>>()?;
        host.forwards = record.forwards.iter().map(PortForwardRecord::to_model).collect::<Result<_, _>>()?;
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
                    HostAuth::Agent => model::AuthMethod::Agent,
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

    pub fn generate_key(
        &self,
        label: String,
        algorithm: KeyAlgorithm,
        passphrase: Option<String>,
    ) -> Result<KeyRecord, CoreError> {
        use termiux_keys::KeyType;
        let kind = match algorithm {
            KeyAlgorithm::Ed25519 => KeyType::Ed25519,
            KeyAlgorithm::EcdsaP256 => KeyType::EcdsaP256,
            KeyAlgorithm::EcdsaP384 => KeyType::EcdsaP384,
            KeyAlgorithm::Rsa3072 => KeyType::Rsa { bits: 3072 },
            KeyAlgorithm::Rsa4096 => KeyType::Rsa { bits: 4096 },
        };
        let key = self.core.generate_key(&label, kind, passphrase.as_deref().filter(|p| !p.is_empty()))?;
        Ok(KeyRecord::from(&key))
    }

    /// Creates an `sk-ssh-ed25519` key on the plugged-in security key. Blocks until the
    /// key is touched; throws `PinRequired` when the key wants its PIN.
    pub fn generate_security_key(&self, label: String, pin: Option<String>) -> Result<KeyRecord, CoreError> {
        let key = self.core.generate_security_key(&label, pin.as_deref().filter(|p| !p.is_empty()))?;
        Ok(KeyRecord::from(&key))
    }

    /// Registers a hardware-bound key (created or found by the app) by its public key.
    pub fn add_platform_key(
        &self,
        label: String,
        public_key: String,
        key: PlatformKeyRef,
    ) -> Result<KeyRecord, CoreError> {
        let storage = match key {
            PlatformKeyRef::Piv { token_id, slot } => model::KeyStorage::Piv { token_id, slot },
            PlatformKeyRef::SecureEnclave { tag } => model::KeyStorage::SecureEnclave { tag },
        };
        Ok(KeyRecord::from(&self.core.add_platform_key(&label, &public_key, storage)?))
    }

    /// The OpenSSH private key file, optionally encrypted with `passphrase`.
    pub fn export_private_key(&self, id: String, passphrase: Option<String>) -> Result<String, CoreError> {
        Ok(self.core.export_private_key(parse_id(&id)?, passphrase.as_deref().filter(|p| !p.is_empty()))?)
    }

    /// Logs in to the host with its saved credentials and adds the key to authorized_keys.
    pub async fn install_public_key(
        &self,
        host_id: String,
        key_id: String,
        ui: Arc<dyn Interaction>,
    ) -> Result<(), CoreError> {
        let host = self.core.store.host(parse_id(&host_id)?)?.ok_or_else(|| failed("host not found"))?;
        let key_id = parse_id(&key_id)?;
        let core = self.core.clone();
        let port = host.port;
        runtime()
            .spawn(async move {
                let ui: Arc<dyn termiux_session::Interaction> = Arc::new(InteractionAdapter(ui));
                core.install_public_key(host, key_id, ui).await.map_err(|e| CoreError::from_session(e, port))
            })
            .await
            .map_err(failed)?
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

    /// Opens a file browser on a saved host over its own connection.
    pub async fn open_sftp(&self, host_id: String, ui: Arc<dyn Interaction>) -> Result<Arc<FileBrowser>, CoreError> {
        let host = self.core.store.host(parse_id(&host_id)?)?.ok_or_else(|| failed("host not found"))?;
        let core = self.core.clone();
        let port = host.port;
        runtime()
            .spawn(async move {
                let ui: Arc<dyn termiux_session::Interaction> = Arc::new(InteractionAdapter(ui));
                core.open_sftp(host, ui)
                    .await
                    .map(|b| Arc::new(FileBrowser { inner: Arc::new(b) }))
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

    pub async fn forwards(&self) -> Vec<ForwardStatus> {
        self.inner
            .forwards()
            .await
            .iter()
            .map(|f| ForwardStatus {
                forward: PortForwardRecord::from(&f.config),
                running: f.bound.is_some(),
                bound_host: f.bound.as_ref().map(|b| b.0.clone()),
                bound_port: f.bound.as_ref().map(|b| b.1),
                error: f.error.clone(),
            })
            .collect()
    }

    /// Opens a file browser on this session's connection (SSH sessions only).
    pub async fn open_sftp(&self) -> Result<Arc<FileBrowser>, CoreError> {
        Ok(Arc::new(FileBrowser { inner: Arc::new(self.inner.open_sftp().await?) }))
    }

    pub async fn start_forward(&self, id: String) -> Result<(), CoreError> {
        Ok(self.inner.start_forward(parse_id(&id)?).await?)
    }

    pub async fn stop_forward(&self, id: String) -> Result<(), CoreError> {
        self.inner.stop_forward(parse_id(&id)?).await;
        Ok(())
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
            jump_host_ids: Vec::new(),
            forwards: vec![PortForwardRecord {
                id: String::new(),
                kind: ForwardKind::Dynamic,
                bind_host: String::new(),
                bind_port: 1080,
                target_host: String::new(),
                target_port: 0,
                auto_start: true,
            }],
        }
    }

    #[test]
    fn save_host_manages_password_secret() {
        let dir = tempfile::tempdir().unwrap();
        let secrets = Arc::new(Secrets::default());
        let core = TermiuxCore::open(dir.path().to_string_lossy().into(), secrets.clone(), None, None).unwrap();

        let saved = core
            .save_host(record(HostAuth::Password { saved: false }), PasswordChange::Set { password: "pw".into() })
            .unwrap();
        assert!(!saved.id.is_empty());
        assert_eq!(saved.auth, HostAuth::Password { saved: true });
        assert_eq!(saved.term, "xterm-256color");
        assert_eq!(saved.startup_command, None);
        assert_eq!(saved.forwards.len(), 1);
        assert!(!saved.forwards[0].id.is_empty(), "new forwards get an id");
        assert_eq!(saved.forwards[0].bind_host, "127.0.0.1", "bind defaults to loopback");
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

// MARK: SFTP

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct RemoteEntry {
    pub name: String,
    pub path: String,
    pub is_dir: bool,
    pub is_symlink: bool,
    pub size: u64,
    /// Seconds since the Unix epoch.
    pub modified: Option<u32>,
    pub permissions: Option<u32>,
}

impl From<termiux_sftp::Entry> for RemoteEntry {
    fn from(e: termiux_sftp::Entry) -> Self {
        Self {
            name: e.name,
            path: e.path,
            is_dir: e.kind == termiux_sftp::EntryKind::Dir,
            is_symlink: e.kind == termiux_sftp::EntryKind::Symlink,
            size: e.size,
            modified: e.modified,
            permissions: e.permissions,
        }
    }
}

/// Progress of a background transfer. Called on core threads; `on_finished` exactly once.
#[uniffi::export(with_foreign)]
pub trait TransferListener: Send + Sync {
    fn on_progress(&self, done: u64, total: u64);
    /// `error` is `None` on success and "cancelled" when cancelled.
    fn on_finished(&self, error: Option<String>);
}

/// A running upload or download.
#[derive(uniffi::Object)]
pub struct Transfer {
    cancel: Arc<std::sync::atomic::AtomicBool>,
}

#[uniffi::export]
impl Transfer {
    pub fn cancel(&self) {
        self.cancel.store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

#[derive(uniffi::Object)]
pub struct FileBrowser {
    inner: Arc<termiux_session::SftpBrowser>,
}

fn sftp_err(e: termiux_sftp::SftpError) -> CoreError {
    failed(e)
}

impl FileBrowser {
    fn transfer(
        &self,
        listener: Arc<dyn TransferListener>,
        job: impl for<'a> FnOnce(
            Arc<termiux_session::SftpBrowser>,
            termiux_sftp::Progress<'a>,
        ) -> std::pin::Pin<
            Box<dyn Future<Output = Result<u64, termiux_sftp::SftpError>> + Send + 'a>,
        > + Send
        + 'static,
    ) -> Arc<Transfer> {
        let cancel = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (browser, flag) = (self.inner.clone(), cancel.clone());
        runtime().spawn(async move {
            // At most ~10 progress callbacks per second, plus the final one.
            let last = std::sync::Mutex::new(std::time::Instant::now() - std::time::Duration::from_secs(1));
            let report = |done: u64, total: u64| {
                let mut last = last.lock().unwrap_or_else(|e| e.into_inner());
                if done == total || last.elapsed() >= std::time::Duration::from_millis(100) {
                    *last = std::time::Instant::now();
                    listener.on_progress(done, total);
                }
            };
            let result = job(browser, termiux_sftp::Progress { report: &report, cancel: &flag }).await;
            listener.on_finished(result.err().map(|e| e.to_string()));
        });
        Arc::new(Transfer { cancel })
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl FileBrowser {
    pub async fn home(&self) -> Result<String, CoreError> {
        self.inner.sftp.home().await.map_err(sftp_err)
    }

    pub async fn list(&self, path: String) -> Result<Vec<RemoteEntry>, CoreError> {
        Ok(self.inner.sftp.list(&path).await.map_err(sftp_err)?.into_iter().map(RemoteEntry::from).collect())
    }

    pub async fn mkdir(&self, path: String) -> Result<(), CoreError> {
        self.inner.sftp.mkdir(&path).await.map_err(sftp_err)
    }

    pub async fn rename(&self, from: String, to: String) -> Result<(), CoreError> {
        self.inner.sftp.rename(&from, &to).await.map_err(sftp_err)
    }

    /// Deletes a file or a whole directory tree.
    pub async fn remove(&self, path: String) -> Result<(), CoreError> {
        self.inner.sftp.remove(&path).await.map_err(sftp_err)
    }

    /// Downloads a file or folder to `local_path` in the background.
    pub fn download(
        &self,
        remote_path: String,
        local_path: String,
        listener: Arc<dyn TransferListener>,
    ) -> Arc<Transfer> {
        self.transfer(listener, move |browser, progress| {
            Box::pin(
                async move { browser.sftp.download(&remote_path, std::path::Path::new(&local_path), &progress).await },
            )
        })
    }

    /// Uploads a local file or folder to `remote_path` in the background.
    pub fn upload(
        &self,
        local_path: String,
        remote_path: String,
        listener: Arc<dyn TransferListener>,
    ) -> Arc<Transfer> {
        self.transfer(listener, move |browser, progress| {
            Box::pin(
                async move { browser.sftp.upload(std::path::Path::new(&local_path), &remote_path, &progress).await },
            )
        })
    }

    pub async fn close(&self) {
        self.inner.close().await;
    }
}

// MARK: sync

const VAULT_KEY_SECRET: &str = "sync.vault-key";
const INCLUDE_SECRETS_KEY: &str = "sync.include-secrets";

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SyncSettings {
    /// This device belongs to a vault (has its key).
    pub enabled: bool,
    pub include_secrets: bool,
    pub device_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SyncReport {
    pub received: u32,
    pub sent: u32,
    pub devices: u32,
}

fn sync_err(e: termiux_sync::SyncError) -> CoreError {
    match e {
        termiux_sync::SyncError::InvalidCode => CoreError::Failed { message: e.to_string() },
        other => failed(other),
    }
}

impl TermiuxCore {
    fn vault_key(&self) -> Result<Option<termiux_sync::VaultKey>, CoreError> {
        let secret = model::SecretRef(VAULT_KEY_SECRET.into());
        match self.core.secrets.get(&secret).map_err(failed)? {
            Some(bytes) => Ok(Some(termiux_sync::VaultKey::from_bytes(&bytes).map_err(sync_err)?)),
            None => Ok(None),
        }
    }

    fn store_vault_key(&self, key: &termiux_sync::VaultKey) -> Result<(), CoreError> {
        termiux_sync::reset(&self.core.store).map_err(sync_err)?;
        self.core.secrets.set(&model::SecretRef(VAULT_KEY_SECRET.into()), key.as_bytes()).map_err(failed)
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl TermiuxCore {
    pub fn sync_settings(&self) -> Result<SyncSettings, CoreError> {
        Ok(SyncSettings {
            enabled: self.vault_key()?.is_some(),
            include_secrets: self.core.store.get_value(INCLUDE_SECRETS_KEY)?.is_some_and(|v| v == b"1"),
            device_id: termiux_sync::device_id(&self.core.store).map_err(sync_err)?,
        })
    }

    /// Starts a new vault on this device and returns its sync code for other devices.
    pub fn create_vault(&self) -> Result<String, CoreError> {
        let key = termiux_sync::VaultKey::generate().map_err(sync_err)?;
        self.store_vault_key(&key)?;
        Ok(key.to_code())
    }

    /// Joins an existing vault with a sync code from another device.
    pub fn join_vault(&self, code: String) -> Result<(), CoreError> {
        let key = termiux_sync::VaultKey::from_code(&code).map_err(sync_err)?;
        self.store_vault_key(&key)
    }

    /// The sync code, to set up another device.
    pub fn vault_code(&self) -> Result<Option<String>, CoreError> {
        Ok(self.vault_key()?.map(|k| k.to_code()))
    }

    /// Stops syncing on this device. Local data stays.
    pub fn leave_vault(&self) -> Result<(), CoreError> {
        self.core.secrets.delete(&model::SecretRef(VAULT_KEY_SECRET.into())).map_err(failed)?;
        termiux_sync::reset(&self.core.store).map_err(sync_err)
    }

    pub fn set_sync_include_secrets(&self, include: bool) -> Result<(), CoreError> {
        Ok(self.core.store.set_value(INCLUDE_SECRETS_KEY, if include { b"1" } else { b"0" })?)
    }

    /// Runs one sync round through a shared folder.
    pub async fn sync_folder(&self, folder: String) -> Result<SyncReport, CoreError> {
        let key = self.vault_key()?.ok_or_else(|| failed("sync is not set up"))?;
        let include_secrets = self.sync_settings()?.include_secrets;
        let core = self.core.clone();
        runtime()
            .spawn_blocking(move || {
                let engine = termiux_sync::SyncEngine {
                    store: &core.store,
                    secrets: core.secrets.as_ref(),
                    key: &key,
                    include_secrets,
                };
                engine.sync(&termiux_sync::FolderTransport { dir: folder.into() }).map_err(sync_err)
            })
            .await
            .map_err(failed)?
            .map(|r| SyncReport { received: r.received as u32, sent: r.sent as u32, devices: r.devices as u32 })
    }
}
