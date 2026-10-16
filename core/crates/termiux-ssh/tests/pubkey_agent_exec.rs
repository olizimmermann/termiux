//! Public-key auth via ssh-agent and external signers, and command execution, against an
//! in-process russh server. The agent test uses the system `ssh-agent`/`ssh-add`.

use std::process::Command;
use std::sync::{Arc, Mutex};

use russh::keys::ssh_key::LineEnding;
use russh::keys::{PrivateKey, PublicKey, decode_secret_key, signature::Signer};
use russh::server::{self, Auth, ChannelOpenHandle, Msg, Session};
use russh::{Channel, ChannelId, MethodKind, MethodSet};
use termiux_model::Host;
use termiux_ssh::{BlobSigner, Credential, HostKeyError, HostKeyVerifier, SshError, SshSession};
use tokio::net::TcpListener;

const HOST_KEY: &str = include_str!("fixtures/host_key_a");

struct Server {
    allowed: Vec<PublicKey>,
}

impl server::Handler for Server {
    type Error = russh::Error;

    async fn auth_publickey_offered(&mut self, _: &str, key: &PublicKey) -> Result<Auth, Self::Error> {
        Ok(if self.allowed.iter().any(|k| k.key_data() == key.key_data()) { Auth::Accept } else { Auth::reject() })
    }

    async fn auth_publickey(&mut self, _: &str, key: &PublicKey) -> Result<Auth, Self::Error> {
        self.auth_publickey_offered("", key).await
    }

    async fn channel_open_session(
        &mut self,
        _: Channel<Msg>,
        reply: ChannelOpenHandle,
        _: &mut Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        session.data(channel, format!("ran: {}", String::from_utf8_lossy(data)).into_bytes())?;
        session.exit_status_request(channel, 7)?;
        session.eof(channel)?;
        session.close(channel)?;
        Ok(())
    }
}

async fn spawn_server(allowed: Vec<PublicKey>) -> u16 {
    let config = Arc::new(server::Config {
        keys: vec![decode_secret_key(HOST_KEY, None).unwrap()],
        methods: MethodSet::from(&[MethodKind::PublicKey][..]),
        auth_rejection_time: std::time::Duration::from_millis(10),
        ..Default::default()
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            let handler = Server { allowed: allowed.clone() };
            let session = server::run_stream(config.clone(), socket, handler);
            tokio::spawn(async move {
                if let Ok(s) = session.await {
                    let _ = s.await;
                }
            });
        }
    });
    port
}

struct AcceptAll;
impl HostKeyVerifier for AcceptAll {
    fn verify(&self, _: &str, _: u16, _: &PublicKey) -> Result<(), HostKeyError> {
        Ok(())
    }
}

fn host(port: u16) -> Host {
    let mut host = Host::new("t", "127.0.0.1", "tester");
    host.port = port;
    host
}

/// Signs with a software key but through the external-signer path (as PIV/Secure Enclave do).
struct SoftwareBlobSigner {
    key: PrivateKey,
    calls: Mutex<usize>,
}

impl BlobSigner for SoftwareBlobSigner {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        *self.calls.lock().unwrap() += 1;
        let sig: russh::keys::ssh_key::Signature = self.key.try_sign(data).map_err(|e| e.to_string())?;
        let alg = sig.algorithm().to_string();
        let mut blob = Vec::new();
        for part in [alg.as_bytes(), sig.as_bytes()] {
            blob.extend_from_slice(&(part.len() as u32).to_be_bytes());
            blob.extend_from_slice(part);
        }
        Ok(blob)
    }
}

#[tokio::test]
async fn external_signer_auth_and_exec() {
    let key = termiux_keys::generate(termiux_keys::KeyType::EcdsaP256, "piv").unwrap();
    let port = spawn_server(vec![key.public_key().clone()]).await;
    let signer = Arc::new(SoftwareBlobSigner { key: key.clone(), calls: Mutex::new(0) });
    let credential = Credential::External { public_key: key.public_key().clone(), signer: signer.clone() };
    let session = SshSession::connect(&host(port), credential, Arc::new(AcceptAll)).await.unwrap();
    assert_eq!(*signer.calls.lock().unwrap(), 1);

    let (status, output) = session.exec("echo hi").await.unwrap();
    assert_eq!(status, Some(7));
    assert_eq!(String::from_utf8_lossy(&output), "ran: echo hi");
}

#[tokio::test]
async fn external_signer_wrong_key_rejected() {
    let allowed = termiux_keys::generate(termiux_keys::KeyType::Ed25519, "").unwrap();
    let other = termiux_keys::generate(termiux_keys::KeyType::Ed25519, "").unwrap();
    let port = spawn_server(vec![allowed.public_key().clone()]).await;
    let signer = Arc::new(SoftwareBlobSigner { key: other.clone(), calls: Mutex::new(0) });
    let credential = Credential::External { public_key: other.public_key().clone(), signer };
    let result = SshSession::connect(&host(port), credential, Arc::new(AcceptAll)).await;
    assert!(matches!(result, Err(SshError::AuthRejected)));
}

/// Starts a private ssh-agent with one key loaded. Returns (socket path, agent pid, tempdir).
fn start_agent(key: &PrivateKey) -> (std::path::PathBuf, String, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("agent.sock");
    let out = Command::new("ssh-agent").arg("-a").arg(&socket).arg("-s").output().expect("ssh-agent");
    let text = String::from_utf8_lossy(&out.stdout);
    let pid = text.split("SSH_AGENT_PID=").nth(1).unwrap().split(';').next().unwrap().to_string();
    let key_path = dir.path().join("id");
    std::fs::write(&key_path, key.to_openssh(LineEnding::LF).unwrap().as_bytes()).unwrap();
    std::fs::set_permissions(&key_path, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
    let added = Command::new("ssh-add").arg(&key_path).env("SSH_AUTH_SOCK", &socket).output().unwrap();
    assert!(added.status.success(), "{}", String::from_utf8_lossy(&added.stderr));
    (socket, pid, dir)
}

#[tokio::test]
async fn agent_auth_tries_identities() {
    let decoy = termiux_keys::generate(termiux_keys::KeyType::Ed25519, "decoy").unwrap();
    let key = termiux_keys::generate(termiux_keys::KeyType::Ed25519, "agent").unwrap();
    // The decoy is offered first and rejected, so the identity loop is exercised.
    let (socket, pid, dir) = start_agent(&decoy);
    let key_path = dir.path().join("real");
    std::fs::write(&key_path, key.to_openssh(LineEnding::LF).unwrap().as_bytes()).unwrap();
    std::fs::set_permissions(&key_path, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
    Command::new("ssh-add").arg(&key_path).env("SSH_AUTH_SOCK", &socket).output().unwrap();

    let port = spawn_server(vec![key.public_key().clone()]).await;
    let result =
        SshSession::connect(&host(port), Credential::Agent { socket: Some(socket.clone()) }, Arc::new(AcceptAll)).await;
    let _ = Command::new("kill").arg(&pid).status();
    result.unwrap();
}

#[tokio::test]
async fn agent_missing_socket_is_an_error() {
    let port = spawn_server(vec![]).await;
    let result = SshSession::connect(
        &host(port),
        Credential::Agent { socket: Some("/nonexistent/agent.sock".into()) },
        Arc::new(AcceptAll),
    )
    .await;
    assert!(matches!(result, Err(SshError::Agent(_))));
}
