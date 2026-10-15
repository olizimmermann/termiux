//! UniFFI surface consumed by the Swift (and later Kotlin) apps.

use std::sync::{Arc, OnceLock};

use russh::keys::{HashAlg, PublicKey};
use termiux_model::Host;
use termiux_ssh::{Credential, HostKeyVerifier, Shell, SshSession};

uniffi::setup_scaffolding!();

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum CoreError {
    #[error("{message}")]
    Connection { message: String },
    #[error("authentication rejected")]
    AuthRejected,
}

impl From<termiux_ssh::SshError> for CoreError {
    fn from(e: termiux_ssh::SshError) -> Self {
        match e {
            termiux_ssh::SshError::AuthRejected => CoreError::AuthRejected,
            other => CoreError::Connection { message: other.to_string() },
        }
    }
}

/// Implemented by the UI layer: receives terminal output and lifecycle events.
#[uniffi::export(with_foreign)]
pub trait TerminalListener: Send + Sync {
    fn on_output(&self, data: Vec<u8>);
    fn on_exit(&self, exit_status: Option<u32>);
}

/// Implemented by the UI layer: asks the user / known_hosts store whether to trust a host key.
#[uniffi::export(with_foreign)]
pub trait HostKeyPrompt: Send + Sync {
    fn trust(&self, host: String, port: u16, algorithm: String, sha256_fingerprint: String) -> bool;
}

struct PromptVerifier(Arc<dyn HostKeyPrompt>);

impl HostKeyVerifier for PromptVerifier {
    fn verify(&self, host: &str, port: u16, key: &PublicKey) -> bool {
        self.0.trust(
            host.to_string(),
            port,
            key.algorithm().to_string(),
            key.fingerprint(HashAlg::Sha256).to_string(),
        )
    }
}

#[derive(uniffi::Record)]
pub struct ConnectParams {
    pub hostname: String,
    pub port: u16,
    pub username: String,
    pub password: Option<String>,
    pub private_key: Option<String>,
    pub passphrase: Option<String>,
    pub cols: u32,
    pub rows: u32,
}

#[derive(uniffi::Object)]
pub struct TerminalSession {
    session: SshSession,
    shell: Shell,
}

#[uniffi::export(async_runtime = "tokio")]
impl TerminalSession {
    pub fn write(&self, data: Vec<u8>) {
        self.shell.write(&data);
    }

    pub fn resize(&self, cols: u32, rows: u32) {
        self.shell.resize(cols, rows);
    }

    pub async fn disconnect(&self) {
        let _ = self.session.disconnect().await;
    }
}

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

#[uniffi::export(async_runtime = "tokio")]
pub async fn connect_ssh(
    params: ConnectParams,
    prompt: Arc<dyn HostKeyPrompt>,
    listener: Arc<dyn TerminalListener>,
) -> Result<Arc<TerminalSession>, CoreError> {
    // Run on our own runtime so sessions outlive whichever executor polled this future.
    runtime()
        .spawn(async move {
            let mut host = Host::new(&params.hostname, &params.hostname, &params.username);
            host.port = params.port;
            let credential = match (params.private_key, params.password) {
                (Some(openssh), _) => Credential::PrivateKey { openssh, passphrase: params.passphrase },
                (None, Some(pw)) => Credential::Password(pw),
                (None, None) => return Err(CoreError::AuthRejected),
            };
            let session = SshSession::connect(&host, credential, Arc::new(PromptVerifier(prompt))).await?;
            let out = listener.clone();
            let shell = session
                .open_shell("xterm-256color", params.cols, params.rows, move |b| out.on_output(b.to_vec()), move |s| {
                    listener.on_exit(s)
                })
                .await?;
            Ok(Arc::new(TerminalSession { session, shell }))
        })
        .await
        .map_err(|e| CoreError::Connection { message: e.to_string() })?
}
