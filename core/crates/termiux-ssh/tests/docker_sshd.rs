//! Integration tests against a local OpenSSH server. Run with `scripts/test-sshd.sh`,
//! which starts the container and sets TERMIUX_TEST_KEY.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use russh::keys::PublicKey;
use termiux_model::{AuthMethod, Host};
use termiux_ssh::{Credential, HostKeyError, HostKeyVerifier, SshError, SshSession};
use tokio::sync::oneshot;

struct AcceptAll;
impl HostKeyVerifier for AcceptAll {
    fn verify(&self, _: &str, _: u16, _: &PublicKey) -> Result<(), HostKeyError> {
        Ok(())
    }
}

struct RejectAll;
impl HostKeyVerifier for RejectAll {
    fn verify(&self, host: &str, _: u16, _: &PublicKey) -> Result<(), HostKeyError> {
        Err(HostKeyError::NotTrusted { host: host.into(), fingerprint: String::new() })
    }
}

fn test_host() -> Host {
    let mut host = Host::new("docker", "127.0.0.1", "termiux");
    host.port = 2222;
    host
}

async fn run_echo(session: &SshSession) -> String {
    let output = Arc::new(Mutex::new(Vec::new()));
    let sink = output.clone();
    let (done_tx, done_rx) = oneshot::channel();
    let shell = session
        .open_shell(
            "xterm-256color",
            80,
            24,
            move |b| sink.lock().unwrap().extend_from_slice(b),
            move |_| {
                let _ = done_tx.send(());
            },
        )
        .await
        .unwrap();
    shell.resize(120, 40);
    shell.write(b"stty size; echo termiux-$((40+2)); exit\n");
    tokio::time::timeout(Duration::from_secs(10), done_rx).await.unwrap().unwrap();
    String::from_utf8_lossy(&output.lock().unwrap()).into_owned()
}

#[tokio::test]
#[ignore = "needs docker sshd"]
async fn password_auth_shell() {
    let session = SshSession::connect(
        &test_host(),
        Credential::Password { password: "termiux".into(), fallback: None },
        Arc::new(AcceptAll),
    )
    .await
    .unwrap();
    let out = run_echo(&session).await;
    assert!(out.contains("termiux-42"), "{out}");
    assert!(out.contains("40 120"), "resize not applied: {out}");
}

#[tokio::test]
#[ignore = "needs docker sshd"]
async fn key_auth_shell() {
    let key = std::fs::read_to_string(std::env::var("TERMIUX_TEST_KEY").unwrap()).unwrap();
    let mut host = test_host();
    host.auth = AuthMethod::Key { key_id: uuid::Uuid::nil() };
    let session =
        SshSession::connect(&host, Credential::PrivateKey { openssh: key, passphrase: None }, Arc::new(AcceptAll))
            .await
            .unwrap();
    assert!(run_echo(&session).await.contains("termiux-42"));
}

#[tokio::test]
#[ignore = "needs docker sshd"]
async fn wrong_password_rejected() {
    let err = SshSession::connect(
        &test_host(),
        Credential::Password { password: "nope".into(), fallback: None },
        Arc::new(AcceptAll),
    )
    .await;
    assert!(matches!(err, Err(SshError::AuthRejected)));
}

#[tokio::test]
#[ignore = "needs docker sshd"]
async fn untrusted_host_key_rejected() {
    let err = SshSession::connect(
        &test_host(),
        Credential::Password { password: "termiux".into(), fallback: None },
        Arc::new(RejectAll),
    )
    .await;
    assert!(matches!(err, Err(SshError::HostKey(HostKeyError::NotTrusted { .. }))));
}

#[tokio::test]
#[ignore = "needs docker sshd"]
async fn local_forward_through_openssh() {
    use tokio::io::AsyncReadExt;
    let session = Arc::new(
        SshSession::connect(
            &test_host(),
            Credential::Password { password: "termiux".into(), fallback: None },
            Arc::new(AcceptAll),
        )
        .await
        .unwrap(),
    );
    // Forward to the container's own sshd and expect its banner.
    let fwd = termiux_ssh::forward::local(session, "127.0.0.1", 0, "127.0.0.1", 2222).await.unwrap();
    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", fwd.bound.1)).await.unwrap();
    let mut banner = [0u8; 7];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut banner)).await.unwrap().unwrap();
    assert_eq!(&banner, b"SSH-2.0");
}
