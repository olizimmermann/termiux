//! Turns saved hosts into running terminal sessions: resolves credentials from the
//! secret store, imports keys, and puts SSH and local shells behind one session type.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use russh::keys::ssh_key::private::KeypairData;
use russh::keys::ssh_key::{LineEnding, PrivateKey};
use termiux_model::{AuthMethod, EndReason, Host, Key, KeyStorage, SecretRef, SessionEnd, now};
use termiux_pty::{LocalShell, ShellOptions};
use termiux_ssh::{
    Credential, HostKeyInfo, KeyboardInteractiveResponder, KnownHostsVerifier, NewHostPrompt, Shell, SshError,
    SshSession,
};
use termiux_store::{SecretError, SecretStore, Store, StoreError};
use uuid::Uuid;

pub use termiux_ssh::HostKeyError;

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Secret(#[from] SecretError),
    #[error(transparent)]
    Ssh(#[from] SshError),
    #[error(transparent)]
    Pty(#[from] termiux_pty::PtyError),
    #[error("key {0} not found")]
    MissingKey(Uuid),
    #[error("secret for {0} is missing from the secret store")]
    MissingSecret(String),
    #[error("invalid key: {0}")]
    InvalidKey(String),
    #[error("not supported yet: {0}")]
    Unsupported(&'static str),
    #[error("cancelled")]
    Cancelled,
}

/// Everything the core may need to ask the user while connecting. All methods may block
/// (they are called off the async workers).
pub trait Interaction: Send + Sync + 'static {
    fn confirm_new_host(&self, info: &HostKeyInfo) -> bool;
    /// Server-driven prompts as `(text, echo)` pairs; `None` cancels.
    fn keyboard_interactive(&self, name: &str, instructions: &str, prompts: &[(String, bool)]) -> Option<Vec<String>>;
    /// Asks for a single secret (password, key passphrase); `None` cancels.
    fn ask_secret(&self, title: &str, message: &str) -> Option<String>;
    /// Non-blocking status for the UI, e.g. "Touch your security key".
    fn status(&self, _message: &str) {}
}

struct PromptAdapter(Arc<dyn Interaction>);

impl NewHostPrompt for PromptAdapter {
    fn confirm_new_host(&self, info: &HostKeyInfo) -> bool {
        self.0.confirm_new_host(info)
    }
}

impl KeyboardInteractiveResponder for PromptAdapter {
    fn respond(&self, name: &str, instructions: &str, prompts: &[(String, bool)]) -> Option<Vec<String>> {
        self.0.keyboard_interactive(name, instructions, prompts)
    }
}

/// Receives terminal output and the end of the session. Called from core threads.
pub trait TerminalSink: Send + Sync + 'static {
    fn output(&self, data: &[u8]);
    fn ended(&self, end: SessionEnd);
}

pub struct Core {
    pub store: Arc<Store>,
    pub secrets: Arc<dyn SecretStore>,
}

fn secret_string(secrets: &dyn SecretStore, secret: &SecretRef) -> Result<String, SessionError> {
    let bytes = secrets.get(secret)?.ok_or_else(|| SessionError::MissingSecret(secret.0.clone()))?;
    String::from_utf8(bytes).map_err(|_| SessionError::MissingSecret(secret.0.clone()))
}

impl Core {
    /// Builds the credential for `host` from its auth settings. Blocking (may prompt).
    pub fn resolve_credential(&self, host: &Host, ui: &Arc<dyn Interaction>) -> Result<Credential, SessionError> {
        let fallback: Arc<dyn KeyboardInteractiveResponder> = Arc::new(PromptAdapter(ui.clone()));
        match &host.auth {
            AuthMethod::Password { secret } => {
                let password = match secret {
                    Some(secret) => secret_string(self.secrets.as_ref(), secret)?,
                    None => ui
                        .ask_secret("Password", &format!("Password for {}@{}", host.username, host.hostname))
                        .ok_or(SessionError::Cancelled)?,
                };
                Ok(Credential::Password { password, fallback: Some(fallback) })
            }
            AuthMethod::KeyboardInteractive => Ok(Credential::KeyboardInteractive(fallback)),
            AuthMethod::Key { key_id } => {
                let key = self.store.key(*key_id)?.ok_or(SessionError::MissingKey(*key_id))?;
                self.key_credential(&key, ui)
            }
            AuthMethod::Agent => Err(SessionError::Unsupported("ssh-agent authentication")),
        }
    }

    fn key_credential(&self, key: &Key, ui: &Arc<dyn Interaction>) -> Result<Credential, SessionError> {
        match &key.storage {
            KeyStorage::Software { secret, passphrase } => {
                let openssh = secret_string(self.secrets.as_ref(), secret)?;
                let passphrase = match passphrase {
                    Some(p) => Some(secret_string(self.secrets.as_ref(), p)?),
                    None if PrivateKey::from_openssh(&openssh).is_ok_and(|k| k.is_encrypted()) => Some(
                        ui.ask_secret("Key passphrase", &format!("Passphrase for key “{}”", key.label))
                            .ok_or(SessionError::Cancelled)?,
                    ),
                    None => None,
                };
                Ok(Credential::PrivateKey { openssh, passphrase })
            }
            KeyStorage::SecurityKey { key_handle } => {
                let file = secret_string(self.secrets.as_ref(), key_handle)?;
                let sk =
                    termiux_fido::SkKey::from_openssh(&file).map_err(|e| SessionError::InvalidKey(e.to_string()))?;
                ui.status("Touch your security key");
                Ok(Credential::SecurityKey { key: sk, pin: None })
            }
            KeyStorage::Piv { .. } => Err(SessionError::Unsupported("PIV keys")),
            KeyStorage::SecureEnclave { .. } => Err(SessionError::Unsupported("Secure Enclave keys")),
        }
    }

    /// Imports an OpenSSH private key file (software or FIDO2 `sk-` key). The key material
    /// goes to the secret store; only the public key and references go to the database.
    pub fn import_key(&self, label: &str, openssh: &str, passphrase: Option<&str>) -> Result<Key, SessionError> {
        let parsed = PrivateKey::from_openssh(openssh).map_err(|e| SessionError::InvalidKey(e.to_string()))?;
        let public_key = parsed.public_key().to_openssh().map_err(|e| SessionError::InvalidKey(e.to_string()))?;
        let secret = SecretRef::new();

        let storage = match parsed.key_data() {
            KeypairData::SkEd25519(_) | KeypairData::SkEcdsaSha2NistP256(_) => {
                self.secrets.set(&secret, openssh.as_bytes())?;
                KeyStorage::SecurityKey { key_handle: secret }
            }
            _ => {
                // Validate the passphrase now rather than failing at connect time.
                if parsed.is_encrypted() {
                    let pass = passphrase.ok_or(SessionError::InvalidKey("key is encrypted".into()))?;
                    parsed.decrypt(pass).map_err(|_| SessionError::InvalidKey("wrong passphrase".into()))?;
                }
                let normalized =
                    parsed.to_openssh(LineEnding::LF).map_err(|e| SessionError::InvalidKey(e.to_string()))?;
                self.secrets.set(&secret, normalized.as_bytes())?;
                let passphrase = match passphrase.filter(|_| parsed.is_encrypted()) {
                    Some(p) => {
                        let r = SecretRef::new();
                        self.secrets.set(&r, p.as_bytes())?;
                        Some(r)
                    }
                    None => None,
                };
                KeyStorage::Software { secret, passphrase }
            }
        };

        let key = Key { id: Uuid::new_v4(), label: label.to_string(), public_key, storage, updated_at: now() };
        self.store.save_key(&key)?;
        Ok(key)
    }

    /// Deletes a key record and its secrets.
    pub fn delete_key(&self, id: Uuid) -> Result<(), SessionError> {
        if let Some(key) = self.store.key(id)? {
            match &key.storage {
                KeyStorage::Software { secret, passphrase } => {
                    self.secrets.delete(secret)?;
                    if let Some(p) = passphrase {
                        self.secrets.delete(p)?;
                    }
                }
                KeyStorage::SecurityKey { key_handle } => self.secrets.delete(key_handle)?,
                KeyStorage::Piv { .. } | KeyStorage::SecureEnclave { .. } => {}
            }
            self.store.delete_key(id)?;
        }
        Ok(())
    }

    /// Sets (or clears) the stored password for a host.
    pub fn set_host_password(&self, host: &mut Host, password: Option<&str>) -> Result<(), SessionError> {
        if let AuthMethod::Password { secret: Some(old) } = &host.auth {
            self.secrets.delete(old)?;
        }
        let secret = match password {
            Some(p) => {
                let r = SecretRef::new();
                self.secrets.set(&r, p.as_bytes())?;
                Some(r)
            }
            None => None,
        };
        host.auth = AuthMethod::Password { secret };
        host.updated_at = now();
        self.store.save_host(host)?;
        Ok(())
    }

    /// Connects to a saved host and opens an interactive shell.
    pub async fn connect(
        &self,
        host: Host,
        cols: u32,
        rows: u32,
        ui: Arc<dyn Interaction>,
        sink: Arc<dyn TerminalSink>,
    ) -> Result<TerminalSession, SessionError> {
        let (core_store, secrets) = (self.store.clone(), self.secrets.clone());
        let resolve_host = host.clone();
        let resolve_ui = ui.clone();
        // Resolving may prompt the user; keep it off the async workers.
        let credential = tokio::task::spawn_blocking(move || {
            Core { store: core_store, secrets }.resolve_credential(&resolve_host, &resolve_ui)
        })
        .await
        .map_err(|_| SessionError::Cancelled)??;

        let verifier = Arc::new(KnownHostsVerifier { store: self.store.clone(), prompt: Arc::new(PromptAdapter(ui)) });
        let session = SshSession::connect(&host, credential, verifier).await?;
        let out = sink.clone();
        let shell =
            session.open_shell(&host.term, cols, rows, move |b| out.output(b), move |end| sink.ended(end)).await?;
        if let Some(cmd) = host.startup_command.as_deref().filter(|c| !c.trim().is_empty()) {
            shell.write(format!("{cmd}\n").as_bytes());
        }
        Ok(TerminalSession(Inner::Ssh { session: Arc::new(session), shell }))
    }

    /// Starts a local shell (not available in sandboxed builds).
    pub fn open_local_shell(
        &self,
        options: ShellOptions,
        sink: Arc<dyn TerminalSink>,
    ) -> Result<TerminalSession, SessionError> {
        let killed = Arc::new(AtomicBool::new(false));
        let flag = killed.clone();
        let out = sink.clone();
        let shell = LocalShell::spawn(
            options,
            move |b| out.output(b),
            move |code| {
                let reason = if flag.load(Ordering::SeqCst) { EndReason::UserClosed } else { EndReason::Exited };
                sink.ended(SessionEnd { exit_status: code, reason });
            },
        )?;
        Ok(TerminalSession(Inner::Local { shell, killed }))
    }
}

enum Inner {
    Ssh { session: Arc<SshSession>, shell: Shell },
    Local { shell: LocalShell, killed: Arc<AtomicBool> },
}

/// A running terminal session, SSH or local.
pub struct TerminalSession(Inner);

impl TerminalSession {
    pub fn write(&self, data: &[u8]) {
        match &self.0 {
            Inner::Ssh { shell, .. } => shell.write(data),
            Inner::Local { shell, .. } => {
                let _ = shell.write(data);
            }
        }
    }

    pub fn resize(&self, cols: u32, rows: u32) {
        match &self.0 {
            Inner::Ssh { shell, .. } => shell.resize(cols, rows),
            Inner::Local { shell, .. } => {
                let clamp = |v: u32| v.min(u16::MAX as u32) as u16;
                let _ = shell.resize(clamp(cols), clamp(rows));
            }
        }
    }

    /// Ends the session; the sink receives `EndReason::UserClosed`.
    pub async fn close(&self) {
        match &self.0 {
            Inner::Ssh { session, shell } => {
                shell.mark_user_closed();
                let _ = session.disconnect().await;
            }
            Inner::Local { shell, killed } => {
                killed.store(true, Ordering::SeqCst);
                let _ = shell.kill();
            }
        }
    }
}
