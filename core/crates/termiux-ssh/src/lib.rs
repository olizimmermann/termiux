//! SSH client sessions built on russh.

use std::sync::Arc;
use std::time::Duration;

use russh::client::{self, Handle};
use russh::keys::{HashAlg, PrivateKeyWithHashAlg, PublicKey, PublicKeyOrCertificate, decode_secret_key};
use russh::{ChannelMsg, ChannelWriteHalf};
use termiux_model::Host;
use tokio::sync::mpsc;

#[derive(Debug, thiserror::Error)]
pub enum SshError {
    #[error("ssh: {0}")]
    Russh(#[from] russh::Error),
    #[error("key: {0}")]
    Key(#[from] russh::keys::Error),
    #[error("authentication rejected")]
    AuthRejected,
    #[error("host key rejected for {host}: {fingerprint}")]
    HostKeyRejected { host: String, fingerprint: String },
}

/// Secret material resolved from the platform secret store right before connecting.
pub enum Credential {
    Password(String),
    PrivateKey { openssh: String, passphrase: Option<String> },
}

/// Decides whether a server's host key is trusted (known_hosts / TOFU prompt).
pub trait HostKeyVerifier: Send + Sync + 'static {
    fn verify(&self, host: &str, port: u16, key: &PublicKey) -> bool;
}

struct ClientHandler {
    host: String,
    port: u16,
    verifier: Arc<dyn HostKeyVerifier>,
    rejected: Option<String>,
}

impl client::Handler for ClientHandler {
    type Error = SshError;

    async fn check_server_key(&mut self, server_key: &PublicKeyOrCertificate) -> Result<bool, SshError> {
        let key = match server_key {
            PublicKeyOrCertificate::PublicKey { key, .. } => key,
            // Host certificates are not supported yet; treat as untrusted.
            PublicKeyOrCertificate::Certificate(_) => return Ok(false),
        };
        // The verifier may block on a user prompt; keep it off the async workers.
        let (verifier, host, port, key_owned) = (self.verifier.clone(), self.host.clone(), self.port, key.clone());
        let ok = tokio::task::spawn_blocking(move || verifier.verify(&host, port, &key_owned))
            .await
            .unwrap_or(false);
        if !ok {
            self.rejected = Some(key.fingerprint(HashAlg::Sha256).to_string());
        }
        Ok(ok)
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
        let config = Arc::new(client::Config {
            keepalive_interval: keepalive,
            keepalive_max: 3,
            ..Default::default()
        });
        let handler = ClientHandler {
            host: host.hostname.clone(),
            port: host.port,
            verifier,
            rejected: None,
        };
        let mut handle = client::connect(config, (host.hostname.as_str(), host.port), handler).await?;

        let auth = match credential {
            Credential::Password(password) => handle.authenticate_password(&host.username, password).await?,
            Credential::PrivateKey { openssh, passphrase } => {
                let key = decode_secret_key(&openssh, passphrase.as_deref())?;
                let hash = handle.best_supported_rsa_hash().await?.flatten();
                let key = PrivateKeyWithHashAlg::new(Arc::new(key), hash);
                handle.authenticate_publickey(&host.username, key).await?
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
        self.handle
            .disconnect(russh::Disconnect::ByApplication, "", "en")
            .await?;
        Ok(())
    }
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
