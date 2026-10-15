//! SSH client sessions built on russh.

mod known_hosts;

use std::sync::Arc;
use std::time::Duration;

use russh::client::{self, Handle, KeyboardInteractiveAuthResponse};
use russh::keys::{PrivateKeyWithHashAlg, PublicKey, PublicKeyOrCertificate, decode_secret_key};
use russh::{ChannelMsg, ChannelWriteHalf, MethodKind};
use termiux_model::Host;
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
    Password(String),
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
        let config = Arc::new(client::Config { keepalive_interval: keepalive, keepalive_max: 3, ..Default::default() });
        let handler = ClientHandler { host: host.hostname.clone(), port: host.port, verifier };
        let mut handle = client::connect(config, (host.hostname.as_str(), host.port), handler).await?;

        let auth = match credential {
            Credential::Password(password) => {
                let result = handle.authenticate_password(&host.username, password.clone()).await?;
                match result {
                    // Many servers (PAM) only take passwords through keyboard-interactive.
                    russh::client::AuthResult::Failure { ref remaining_methods, .. }
                        if remaining_methods.contains(&MethodKind::KeyboardInteractive) =>
                    {
                        let responder = PasswordResponder(password);
                        keyboard_interactive(&mut handle, &host.username, &responder).await?
                    }
                    other => other.success(),
                }
                .then_some(())
                .ok_or(SshError::AuthRejected)?;
                return Ok(Self { handle });
            }
            Credential::KeyboardInteractive(responder) => {
                keyboard_interactive(&mut handle, &host.username, responder.as_ref())
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
        on_exit: impl FnOnce(Option<u32>) + Send + 'static,
    ) -> Result<Shell, SshError> {
        let channel = self.handle.channel_open_session().await?;
        channel.request_pty(true, term, cols, rows, 0, 0, &[]).await?;
        channel.request_shell(true).await?;
        let (mut read, write) = channel.split();

        tokio::spawn(async move {
            let mut exit_status = None;
            while let Some(msg) = read.wait().await {
                match msg {
                    ChannelMsg::Data { data } => on_output(&data),
                    ChannelMsg::ExtendedData { data, .. } => on_output(&data),
                    ChannelMsg::ExitStatus { exit_status: s } => exit_status = Some(s),
                    ChannelMsg::Close => break,
                    _ => {}
                }
            }
            on_exit(exit_status);
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

        Ok(Shell { input: input_tx })
    }

    pub async fn disconnect(&self) -> Result<(), SshError> {
        self.handle.disconnect(russh::Disconnect::ByApplication, "", "en").await?;
        Ok(())
    }
}

/// Answers a single hidden prompt with a stored password; refuses anything else.
struct PasswordResponder(String);

impl KeyboardInteractiveResponder for PasswordResponder {
    fn respond(&self, _: &str, _: &str, prompts: &[(String, bool)]) -> Option<Vec<String>> {
        match prompts {
            [] => Some(Vec::new()),
            [(_, false)] => Some(vec![self.0.clone()]),
            _ => None,
        }
    }
}

/// Runs a keyboard-interactive exchange. Returns whether the server accepted it.
async fn keyboard_interactive<H: client::Handler>(
    handle: &mut Handle<H>,
    user: &str,
    responder: &dyn KeyboardInteractiveResponder,
) -> Result<bool, SshError> {
    let mut reply = handle.authenticate_keyboard_interactive_start(user, None).await?;
    // Servers may send several rounds (e.g. password, then OTP); cap to avoid loops.
    for _ in 0..16 {
        match reply {
            KeyboardInteractiveAuthResponse::Success => return Ok(true),
            KeyboardInteractiveAuthResponse::Failure { .. } => return Ok(false),
            KeyboardInteractiveAuthResponse::InfoRequest { name, instructions, prompts } => {
                let prompts: Vec<_> = prompts.into_iter().map(|p| (p.prompt, p.echo)).collect();
                let Some(answers) = responder.respond(&name, &instructions, &prompts) else {
                    return Ok(false);
                };
                if answers.len() != prompts.len() {
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
}

impl Shell {
    pub fn write(&self, bytes: &[u8]) {
        let _ = self.input.send(ShellInput::Data(bytes.to_vec()));
    }

    pub fn resize(&self, cols: u32, rows: u32) {
        let _ = self.input.send(ShellInput::Resize { cols, rows });
    }
}
