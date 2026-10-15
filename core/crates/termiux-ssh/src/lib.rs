//! SSH client sessions built on russh.

mod known_hosts;

use std::sync::Arc;
use std::time::Duration;

use russh::client::{self, Handle, KeyboardInteractiveAuthResponse};
use russh::keys::{Algorithm, PrivateKeyWithHashAlg, PublicKey, PublicKeyOrCertificate, decode_secret_key};
use russh::{ChannelMsg, ChannelWriteHalf, MethodKind, Preferred};
use termiux_model::{EndReason, Host, SessionEnd};
use tokio::sync::mpsc;

pub use known_hosts::{HostKeyInfo, KnownHostsVerifier, NewHostPrompt};

#[derive(Debug, thiserror::Error)]
pub enum SshError {
    #[error("ssh: {0}")]
    Russh(#[from] russh::Error),
    #[error("key: {0}")]
    Key(#[from] russh::keys::Error),
    #[error("authentication rejected")]
    AuthRejected,
    #[error(transparent)]
    SecurityKey(#[from] termiux_fido::SkAuthError),
    #[error(transparent)]
    HostKey(#[from] HostKeyError),
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HostKeyError {
    #[error("host key for {host} not trusted ({fingerprint})")]
    NotTrusted { host: String, fingerprint: String },
    #[error(
        "HOST KEY CHANGED for {host}: now {fingerprint}, previously {previous_fingerprint}. \
         This could be an attack; connection refused"
    )]
    Changed { host: String, fingerprint: String, previous_fingerprint: String },
    #[error("host key check failed: {0}")]
    Internal(String),
}

/// Secret material resolved from the platform secret store right before connecting.
pub enum Credential {
    /// Stored password. If the server asks for more than a single hidden prompt (OTP, a
    /// retry), `fallback` is asked; without one the login fails.
    Password {
        password: String,
        fallback: Option<Arc<dyn KeyboardInteractiveResponder>>,
    },
    PrivateKey {
        openssh: String,
        passphrase: Option<String>,
    },
    /// FIDO2 key on a hardware authenticator; signing needs a touch (and the PIN if set).
    SecurityKey {
        key: termiux_fido::SkKey,
        pin: Option<String>,
    },
    /// Server-driven prompts (OTP codes, PAM conversations, …).
    KeyboardInteractive(Arc<dyn KeyboardInteractiveResponder>),
}

/// Answers keyboard-interactive prompts, typically by asking the user. May block.
pub trait KeyboardInteractiveResponder: Send + Sync + 'static {
    /// `prompts` are `(text, echo)` pairs. Return `None` to cancel.
    fn respond(&self, name: &str, instructions: &str, prompts: &[(String, bool)]) -> Option<Vec<String>>;
}

/// Decides whether a server's host key is trusted. May block on a user prompt.
pub trait HostKeyVerifier: Send + Sync + 'static {
    fn verify(&self, host: &str, port: u16, key: &PublicKey) -> Result<(), HostKeyError>;

    /// Key types already on record for this host (e.g. `ssh-ed25519`). They are offered
    /// first so a change in default preferences never looks like a changed host key.
    fn known_key_types(&self, _host: &str, _port: u16) -> Vec<String> {
        Vec::new()
    }
}

/// russh's default host key preference, reordered so already-known key types come first.
fn host_key_preference(known: &[String]) -> Vec<Algorithm> {
    let key_type = |a: &Algorithm| match a {
        Algorithm::Rsa { .. } => "ssh-rsa".to_string(),
        other => other.as_str().to_string(),
    };
    let mut algs = Preferred::DEFAULT.key.to_vec();
    // Stable sort keeps russh's relative order within each bucket.
    algs.sort_by_key(|a| !known.contains(&key_type(a)));
    algs
}

struct ClientHandler {
    host: String,
    port: u16,
    verifier: Arc<dyn HostKeyVerifier>,
}

impl client::Handler for ClientHandler {
    type Error = SshError;

    async fn check_server_key(&mut self, server_key: &PublicKeyOrCertificate) -> Result<bool, SshError> {
        let key = match server_key {
            PublicKeyOrCertificate::PublicKey { key, .. } => key.clone(),
            // Host certificates are not supported yet; treat as untrusted.
            PublicKeyOrCertificate::Certificate(_) => return Ok(false),
        };
        // The verifier may block on a user prompt; keep it off the async workers.
        let (verifier, host, port) = (self.verifier.clone(), self.host.clone(), self.port);
        tokio::task::spawn_blocking(move || verifier.verify(&host, port, &key))
            .await
            .map_err(|e| HostKeyError::Internal(e.to_string()))??;
        Ok(true)
    }
}

pub struct SshSession {
    handle: Handle<ClientHandler>,
}

impl SshSession {
    pub async fn connect(
        host: &Host,
        credential: Credential,
        verifier: Arc<dyn HostKeyVerifier>,
    ) -> Result<Self, SshError> {
        let keepalive = (host.keepalive_secs > 0).then(|| Duration::from_secs(host.keepalive_secs.into()));
        let preferred = Preferred {
            key: host_key_preference(&verifier.known_key_types(&host.hostname, host.port)).into(),
            ..Preferred::DEFAULT
        };
        let config = Arc::new(client::Config {
            keepalive_interval: keepalive,
            keepalive_max: 3,
            preferred,
            ..Default::default()
        });
        let handler = ClientHandler { host: host.hostname.clone(), port: host.port, verifier };
        let mut handle = client::connect(config, (host.hostname.as_str(), host.port), handler).await?;

        let auth = match credential {
            Credential::Password { password, fallback } => {
                let result = handle.authenticate_password(&host.username, password.clone()).await?;
                match result {
                    // Many servers (PAM) only take passwords through keyboard-interactive.
                    russh::client::AuthResult::Failure { ref remaining_methods, .. }
                        if remaining_methods.contains(&MethodKind::KeyboardInteractive) =>
                    {
                        let responder = Arc::new(PasswordResponder::new(password, fallback));
                        keyboard_interactive(&mut handle, &host.username, responder).await?
                    }
                    other => other.success(),
                }
                .then_some(())
                .ok_or(SshError::AuthRejected)?;
                return Ok(Self { handle });
            }
            Credential::KeyboardInteractive(responder) => {
                keyboard_interactive(&mut handle, &host.username, responder)
                    .await?
                    .then_some(())
                    .ok_or(SshError::AuthRejected)?;
                return Ok(Self { handle });
            }
            Credential::PrivateKey { openssh, passphrase } => {
                let key = decode_secret_key(&openssh, passphrase.as_deref())?;
                let hash = handle.best_supported_rsa_hash().await?.flatten();
                let key = PrivateKeyWithHashAlg::new(Arc::new(key), hash);
                handle.authenticate_publickey(&host.username, key).await?
            }
            Credential::SecurityKey { key, pin } => {
                let public = key.public_key.clone();
                let mut signer = termiux_fido::SkSigner { key, pin };
                handle.authenticate_publickey_with(&host.username, public, None, &mut signer).await?
            }
        };
        if !auth.success() {
            return Err(SshError::AuthRejected);
        }
        Ok(Self { handle })
    }

    /// Opens an interactive shell with a PTY. Output bytes are delivered to `on_output`;
    /// `on_exit` fires once when the channel closes.
    pub async fn open_shell(
        &self,
        term: &str,
        cols: u32,
        rows: u32,
        on_output: impl Fn(&[u8]) + Send + 'static,
        on_exit: impl FnOnce(SessionEnd) + Send + 'static,
    ) -> Result<Shell, SshError> {
        let channel = self.handle.channel_open_session().await?;
        channel.request_pty(true, term, cols, rows, 0, 0, &[]).await?;
        channel.request_shell(true).await?;
        let (mut read, write) = channel.split();
        let user_closed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let closed_flag = user_closed.clone();

        tokio::spawn(async move {
            let mut exit_status = None;
            let mut clean = false;
            while let Some(msg) = read.wait().await {
                match msg {
                    ChannelMsg::Data { data } => on_output(&data),
                    ChannelMsg::ExtendedData { data, .. } => on_output(&data),
                    ChannelMsg::ExitStatus { exit_status: s } => exit_status = Some(s),
                    ChannelMsg::Eof => clean = true,
                    ChannelMsg::Close => {
                        clean = true;
                        break;
                    }
                    _ => {}
                }
            }
            let reason = if closed_flag.load(std::sync::atomic::Ordering::SeqCst) {
                EndReason::UserClosed
            } else if clean || exit_status.is_some() {
                EndReason::Exited
            } else {
                // Stream ended without a close: the transport died (network, sleep, keepalive).
                EndReason::ConnectionLost
            };
            on_exit(SessionEnd { exit_status, reason });
        });

        let (input_tx, mut input_rx) = mpsc::unbounded_channel::<ShellInput>();
        tokio::spawn(async move {
            while let Some(input) = input_rx.recv().await {
                let result = match input {
                    ShellInput::Data(bytes) => write.data_bytes(bytes).await,
                    ShellInput::Resize { cols, rows } => write.window_change(cols, rows, 0, 0).await,
                };
                if result.is_err() {
                    break;
                }
            }
            let _ = close_quietly(&write).await;
        });

        Ok(Shell { input: input_tx, user_closed })
    }

    pub fn is_closed(&self) -> bool {
        self.handle.is_closed()
    }

    pub async fn disconnect(&self) -> Result<(), SshError> {
        self.handle.disconnect(russh::Disconnect::ByApplication, "", "en").await?;
        Ok(())
    }
}

/// Answers the first single hidden prompt with the stored password. Anything else (an OTP,
/// or a re-prompt after a wrong password) goes to the fallback so a bad stored password is
/// never sent twice.
struct PasswordResponder {
    password: std::sync::Mutex<Option<String>>,
    fallback: Option<Arc<dyn KeyboardInteractiveResponder>>,
}

impl PasswordResponder {
    fn new(password: String, fallback: Option<Arc<dyn KeyboardInteractiveResponder>>) -> Self {
        Self { password: std::sync::Mutex::new(Some(password)), fallback }
    }
}

impl KeyboardInteractiveResponder for PasswordResponder {
    fn respond(&self, name: &str, instructions: &str, prompts: &[(String, bool)]) -> Option<Vec<String>> {
        if prompts.is_empty() {
            return Some(Vec::new());
        }
        if let [(_, false)] = prompts
            && let Some(password) = self.password.lock().ok()?.take()
        {
            return Some(vec![password]);
        }
        self.fallback.as_ref()?.respond(name, instructions, prompts)
    }
}

/// Runs a keyboard-interactive exchange. Returns whether the server accepted it.
async fn keyboard_interactive<H: client::Handler>(
    handle: &mut Handle<H>,
    user: &str,
    responder: Arc<dyn KeyboardInteractiveResponder>,
) -> Result<bool, SshError> {
    let mut reply = handle.authenticate_keyboard_interactive_start(user, None).await?;
    // Servers may send several rounds (e.g. password, then OTP); cap to avoid loops.
    for _ in 0..16 {
        match reply {
            KeyboardInteractiveAuthResponse::Success => return Ok(true),
            KeyboardInteractiveAuthResponse::Failure { .. } => return Ok(false),
            KeyboardInteractiveAuthResponse::InfoRequest { name, instructions, prompts } => {
                let prompts: Vec<_> = prompts.into_iter().map(|p| (p.prompt, p.echo)).collect();
                let count = prompts.len();
                // The responder may block on a user prompt; keep it off the async workers.
                let r = responder.clone();
                let answers =
                    tokio::task::spawn_blocking(move || r.respond(&name, &instructions, &prompts)).await.ok().flatten();
                let Some(answers) = answers else {
                    return Ok(false);
                };
                if answers.len() != count {
                    return Ok(false);
                }
                reply = handle.authenticate_keyboard_interactive_respond(answers).await?;
            }
        }
    }
    Ok(false)
}

async fn close_quietly(write: &ChannelWriteHalf<client::Msg>) -> Result<(), russh::Error> {
    write.eof().await?;
    write.close().await
}

enum ShellInput {
    Data(Vec<u8>),
    Resize { cols: u32, rows: u32 },
}

/// Handle for sending input to a running shell. Dropping it closes the channel.
#[derive(Clone)]
pub struct Shell {
    input: mpsc::UnboundedSender<ShellInput>,
    user_closed: Arc<std::sync::atomic::AtomicBool>,
}

impl Shell {
    pub fn write(&self, bytes: &[u8]) {
        let _ = self.input.send(ShellInput::Data(bytes.to_vec()));
    }

    pub fn resize(&self, cols: u32, rows: u32) {
        let _ = self.input.send(ShellInput::Resize { cols, rows });
    }

    /// Marks the session as closed by the user, so the end is reported as `UserClosed`.
    pub fn mark_user_closed(&self) {
        self.user_closed.store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_key_types_lead_preference() {
        let default = Preferred::DEFAULT.key.to_vec();
        assert_eq!(host_key_preference(&[]), default);

        let prefs = host_key_preference(&["ssh-rsa".into()]);
        assert!(matches!(prefs[0], Algorithm::Rsa { .. }));
        assert_eq!(prefs.len(), default.len());

        // A key type at the end of russh's list still moves to the front.
        let ecdsa = default.iter().position(|a| a.as_str() == "ecdsa-sha2-nistp256").unwrap();
        assert!(ecdsa > 0);
        assert_eq!(host_key_preference(&["ecdsa-sha2-nistp256".into()])[0].as_str(), "ecdsa-sha2-nistp256");
    }
}
