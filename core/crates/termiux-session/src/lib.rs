//! Turns saved hosts into running terminal sessions: resolves credentials from the
//! secret store, imports keys, and puts SSH and local shells behind one session type.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use russh::keys::ssh_key::private::KeypairData;
use russh::keys::ssh_key::{LineEnding, PrivateKey};
use termiux_model::{AuthMethod, EndReason, Host, Key, KeyStorage, SecretRef, SessionEnd, now};
use termiux_pty::{LocalShell, ShellOptions};
use termiux_ssh::{
    BlobSigner, Credential, HostKeyInfo, KeyboardInteractiveResponder, KnownHostsVerifier, NewHostPrompt, Shell,
    SshError, SshSession,
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
    #[error(transparent)]
    Fido(#[from] termiux_fido::FidoError),
    #[error(transparent)]
    Keys(#[from] termiux_keys::KeyError),
    #[error("installing the key failed: {0}")]
    InstallFailed(String),
    #[error("jump host {0} not found")]
    MissingJumpHost(Uuid),
    #[error("jump hosts form a loop")]
    JumpLoop,
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

/// Signs with keys held by the platform (PIV smartcards, Secure Enclave). Returns the raw
/// signature: X9.62 DER for ECDSA, PKCS#1 v1.5 SHA-512 for RSA. May block (Touch ID, PIN).
pub trait PlatformSigner: Send + Sync + 'static {
    fn sign(&self, storage: &KeyStorage, data: &[u8]) -> Result<Vec<u8>, String>;
}

struct PlatformBlobSigner {
    platform: Arc<dyn PlatformSigner>,
    storage: KeyStorage,
    public_key: russh::keys::PublicKey,
}

impl BlobSigner for PlatformBlobSigner {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        use russh::keys::ssh_key::Algorithm;
        let raw = self.platform.sign(&self.storage, data)?;
        match self.public_key.algorithm() {
            Algorithm::Ecdsa { curve } => termiux_keys::ecdsa_der_to_ssh(&raw, curve).map_err(|e| e.to_string()),
            Algorithm::Rsa { .. } => Ok(termiux_keys::rsa_sha512_to_ssh(&raw)),
            other => Err(format!("{other} keys cannot be used with platform signing")),
        }
    }
}

pub struct Core {
    pub store: Arc<Store>,
    pub secrets: Arc<dyn SecretStore>,
    /// Hardware-backed keys; `None` on platforms without them.
    pub platform: Option<Arc<dyn PlatformSigner>>,
    /// ssh-agent socket override; `None` uses `SSH_AUTH_SOCK`.
    pub agent_socket: Option<std::path::PathBuf>,
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
            AuthMethod::Agent => Ok(Credential::Agent { socket: self.agent_socket.clone() }),
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
                let prompt_ui = ui.clone();
                let ask_pin: termiux_fido::PinPrompt =
                    Arc::new(move |reason: &str| prompt_ui.ask_secret("Security key PIN", reason));
                Ok(Credential::SecurityKey { key: sk, pin: None, ask_pin: Some(ask_pin) })
            }
            storage @ (KeyStorage::Piv { .. } | KeyStorage::SecureEnclave { .. }) => {
                let platform =
                    self.platform.clone().ok_or(SessionError::Unsupported("hardware keys on this device"))?;
                let public_key = russh::keys::PublicKey::from_openssh(&key.public_key)
                    .map_err(|e| SessionError::InvalidKey(e.to_string()))?;
                if matches!(storage, KeyStorage::Piv { .. }) {
                    ui.status("Enter the smartcard PIN if asked");
                }
                let signer = PlatformBlobSigner { platform, storage: storage.clone(), public_key: public_key.clone() };
                Ok(Credential::External { public_key, signer: Arc::new(signer) })
            }
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

    /// Generates a software key; the private key goes to the secret store.
    pub fn generate_key(
        &self,
        label: &str,
        kind: termiux_keys::KeyType,
        passphrase: Option<&str>,
    ) -> Result<Key, SessionError> {
        let key = termiux_keys::generate(kind, label)?;
        let file = termiux_keys::to_openssh(&key, passphrase)?;
        self.import_key(label, &file, passphrase)
    }

    /// Creates a FIDO2 key on the connected security key. Blocks until touched; fails
    /// with `FidoError::PinRequired` when the key needs its PIN.
    pub fn generate_security_key(&self, label: &str, pin: Option<&str>) -> Result<Key, SessionError> {
        let sk = termiux_fido::generate_ed25519(termiux_fido::DEFAULT_APPLICATION, label, pin)?;
        let file = sk.to_openssh().map_err(|e| SessionError::InvalidKey(e.to_string()))?;
        self.import_key(label, &file, None)
    }

    /// Registers a key that lives in hardware (PIV slot, Secure Enclave) by its public key.
    pub fn add_platform_key(&self, label: &str, public_key: &str, storage: KeyStorage) -> Result<Key, SessionError> {
        let parsed =
            russh::keys::PublicKey::from_openssh(public_key).map_err(|e| SessionError::InvalidKey(e.to_string()))?;
        let mut line = parsed.clone();
        line.set_comment(label);
        let key = Key {
            id: Uuid::new_v4(),
            label: label.to_string(),
            public_key: line.to_openssh().map_err(|e| SessionError::InvalidKey(e.to_string()))?,
            storage,
            updated_at: now(),
        };
        self.store.save_key(&key)?;
        Ok(key)
    }

    /// The private key file for a software key, re-encrypted with `passphrase` if given.
    pub fn export_private_key(&self, id: Uuid, passphrase: Option<&str>) -> Result<String, SessionError> {
        let key = self.store.key(id)?.ok_or(SessionError::MissingKey(id))?;
        match &key.storage {
            KeyStorage::Software { secret, passphrase: stored } => {
                let file = secret_string(self.secrets.as_ref(), secret)?;
                let stored = stored.as_ref().map(|p| secret_string(self.secrets.as_ref(), p)).transpose()?;
                Ok(termiux_keys::export(&file, stored.as_deref(), passphrase)?)
            }
            // The key handle file is all there is to export for FIDO2 keys.
            KeyStorage::SecurityKey { key_handle } => secret_string(self.secrets.as_ref(), key_handle),
            _ => Err(SessionError::Unsupported("exporting hardware-bound keys")),
        }
    }

    /// Connects to `host` with its own credentials and appends `key_id`'s public key to
    /// `~/.ssh/authorized_keys`, unless it is already there.
    pub async fn install_public_key(
        &self,
        host: Host,
        key_id: Uuid,
        ui: Arc<dyn Interaction>,
    ) -> Result<(), SessionError> {
        let key = self.store.key(key_id)?.ok_or(SessionError::MissingKey(key_id))?;
        let session = self.connect_session(&host, ui).await?;
        let script = authorized_keys_script(&key.public_key)?;
        let (status, output) = session.exec_with_input("sh -s", Some(script.as_bytes())).await?;
        let _ = session.disconnect().await;
        match status {
            Some(0) => Ok(()),
            _ => Err(SessionError::InstallFailed(String::from_utf8_lossy(&output).trim().to_string())),
        }
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
    /// Resolves a host's credential off the async workers (it may prompt the user).
    async fn credential_for(&self, host: &Host, ui: &Arc<dyn Interaction>) -> Result<Credential, SessionError> {
        let (store, secrets, platform, agent_socket) =
            (self.store.clone(), self.secrets.clone(), self.platform.clone(), self.agent_socket.clone());
        let (host, ui) = (host.clone(), ui.clone());
        tokio::task::spawn_blocking(move || {
            Core { store, secrets, platform, agent_socket }.resolve_credential(&host, &ui)
        })
        .await
        .map_err(|_| SessionError::Cancelled)?
    }

    /// Connects to `host`, hopping through its jump hosts in order (like ProxyJump). Each
    /// hop uses its own saved credentials and host key check; the jump hosts' own jump
    /// settings are not followed.
    async fn connect_session(&self, host: &Host, ui: Arc<dyn Interaction>) -> Result<SshSession, SessionError> {
        let verifier =
            Arc::new(KnownHostsVerifier { store: self.store.clone(), prompt: Arc::new(PromptAdapter(ui.clone())) });
        let mut seen = std::collections::HashSet::from([host.id]);
        let mut via: Option<Arc<SshSession>> = None;
        for id in &host.jump_hosts {
            if !seen.insert(*id) {
                return Err(SessionError::JumpLoop);
            }
            let jump = self.store.host(*id)?.ok_or(SessionError::MissingJumpHost(*id))?;
            ui.status(&format!("Connecting to jump host {}…", jump.label));
            let credential = self.credential_for(&jump, &ui).await?;
            let session = match via {
                Some(previous) => SshSession::connect_via(previous, &jump, credential, verifier.clone()).await?,
                None => SshSession::connect(&jump, credential, verifier.clone()).await?,
            };
            via = Some(Arc::new(session));
        }
        let credential = self.credential_for(host, &ui).await?;
        Ok(match via {
            Some(previous) => SshSession::connect_via(previous, host, credential, verifier).await?,
            None => SshSession::connect(host, credential, verifier).await?,
        })
    }

    pub async fn connect(
        &self,
        host: Host,
        cols: u32,
        rows: u32,
        ui: Arc<dyn Interaction>,
        sink: Arc<dyn TerminalSink>,
    ) -> Result<TerminalSession, SessionError> {
        let session = self.connect_session(&host, ui).await?;
        let out = sink.clone();
        let shell =
            session.open_shell(&host.term, cols, rows, move |b| out.output(b), move |end| sink.ended(end)).await?;
        if let Some(cmd) = host.startup_command.as_deref().filter(|c| !c.trim().is_empty()) {
            shell.write(format!("{cmd}\n").as_bytes());
        }
        let session = Arc::new(session);
        let forwards = host.forwards.iter().map(|f| ForwardState { config: f.clone(), running: None, error: None });
        let terminal =
            TerminalSession(Inner::Ssh { session, shell, forwards: tokio::sync::Mutex::new(forwards.collect()) });
        for f in host.forwards.iter().filter(|f| f.auto_start) {
            // Failures are recorded per forward and shown in the UI; the shell stays usable.
            let _ = terminal.start_forward(f.id).await;
        }
        Ok(terminal)
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

/// A configured forward on a running session.
pub struct ForwardState {
    pub config: termiux_model::PortForward,
    running: Option<termiux_ssh::forward::Forward>,
    pub error: Option<String>,
}

/// Snapshot of a forward for the UI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardStatus {
    pub config: termiux_model::PortForward,
    /// Where it listens while running.
    pub bound: Option<(String, u16)>,
    pub error: Option<String>,
}

enum Inner {
    Ssh { session: Arc<SshSession>, shell: Shell, forwards: tokio::sync::Mutex<Vec<ForwardState>> },
    Local { shell: LocalShell, killed: Arc<AtomicBool> },
}

/// A running terminal session, SSH or local.
pub struct TerminalSession(Inner);

impl TerminalSession {
    /// Status of every configured forward (empty for local shells).
    pub async fn forwards(&self) -> Vec<ForwardStatus> {
        let Inner::Ssh { forwards, .. } = &self.0 else { return Vec::new() };
        forwards
            .lock()
            .await
            .iter()
            .map(|f| ForwardStatus {
                config: f.config.clone(),
                bound: f.running.as_ref().map(|r| r.bound.clone()),
                error: f.error.clone(),
            })
            .collect()
    }

    /// Starts a configured forward; errors are also recorded in its status.
    pub async fn start_forward(&self, id: Uuid) -> Result<(), SessionError> {
        use termiux_model::ForwardKind;
        use termiux_ssh::forward;
        let Inner::Ssh { session, forwards, .. } = &self.0 else {
            return Err(SessionError::Unsupported("forwards on local shells"));
        };
        let mut forwards = forwards.lock().await;
        let state =
            forwards.iter_mut().find(|f| f.config.id == id).ok_or(SessionError::Unsupported("unknown forward"))?;
        if state.running.is_some() {
            return Ok(());
        }
        let c = state.config.clone();
        let result = match c.kind {
            ForwardKind::Local => {
                forward::local(session.clone(), &c.bind_host, c.bind_port, &c.target_host, c.target_port).await
            }
            ForwardKind::Remote => {
                forward::remote(session.clone(), &c.bind_host, c.bind_port, &c.target_host, c.target_port).await
            }
            ForwardKind::Dynamic => forward::dynamic(session.clone(), &c.bind_host, c.bind_port).await,
        };
        match result {
            Ok(running) => {
                state.running = Some(running);
                state.error = None;
                Ok(())
            }
            Err(e) => {
                state.error = Some(e.to_string());
                Err(e.into())
            }
        }
    }

    pub async fn stop_forward(&self, id: Uuid) {
        let Inner::Ssh { forwards, .. } = &self.0 else { return };
        if let Some(state) = forwards.lock().await.iter_mut().find(|f| f.config.id == id)
            && let Some(running) = state.running.take()
        {
            running.stop().await;
        }
    }

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
            Inner::Ssh { session, shell, forwards } => {
                // Stop listeners first so nothing new is tunnelled into a closing session.
                for state in forwards.lock().await.iter_mut() {
                    if let Some(running) = state.running.take() {
                        running.stop().await;
                    }
                }
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

/// POSIX sh script that adds `public_key` to authorized_keys once, with safe permissions.
fn authorized_keys_script(public_key: &str) -> Result<String, SessionError> {
    let mut parts = public_key.split_whitespace();
    let (Some(alg), Some(blob)) = (parts.next(), parts.next()) else {
        return Err(SessionError::InvalidKey("malformed public key".into()));
    };
    let safe = |s: &str| s.chars().all(|c| c.is_ascii_alphanumeric() || "+/=@.-_".contains(c));
    if !safe(alg) || !safe(blob) {
        return Err(SessionError::InvalidKey("unexpected characters in public key".into()));
    }
    // The comment is dropped: it is free text and not needed for authentication.
    Ok(format!(
        "set -e\numask 077\nmkdir -p \"$HOME/.ssh\"\nf=\"$HOME/.ssh/authorized_keys\"\ntouch \"$f\"\n\
         if ! grep -qF '{alg} {blob}' \"$f\"; then printf '%s\\n' '{alg} {blob} termiux' >> \"$f\"; fi\n\
         chmod 600 \"$f\"\n"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run_script(home: &std::path::Path, script: &str) {
        use std::io::Write;
        let mut child = std::process::Command::new("sh")
            .arg("-s")
            .env("HOME", home)
            .stdin(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(script.as_bytes()).unwrap();
        assert!(child.wait().unwrap().success());
    }

    #[test]
    fn authorized_keys_script_is_idempotent_and_private() {
        use std::os::unix::fs::PermissionsExt;
        let home = tempfile::tempdir().unwrap();
        let script = authorized_keys_script("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBXM my laptop").unwrap();
        run_script(home.path(), &script);
        run_script(home.path(), &script);
        let file = home.path().join(".ssh/authorized_keys");
        let contents = std::fs::read_to_string(&file).unwrap();
        assert_eq!(contents, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBXM termiux\n");
        assert_eq!(std::fs::metadata(&file).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(std::fs::metadata(home.path().join(".ssh")).unwrap().permissions().mode() & 0o777, 0o700);
    }

    #[test]
    fn authorized_keys_script_rejects_injection() {
        assert!(authorized_keys_script("ssh-ed25519 AAAA';rm -rf ~;'").is_err());
        assert!(authorized_keys_script("ssh-ed25519").is_err());
    }
}
