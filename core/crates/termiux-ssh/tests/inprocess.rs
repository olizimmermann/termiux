//! Auth and host-key tests against an in-process russh server (no Docker needed).
//! The fixture host keys are throwaway test keys.

use std::borrow::Cow;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use russh::keys::{PrivateKey, decode_secret_key};
use russh::server::{self, Auth, Response};
use russh::{MethodKind, MethodSet};
use termiux_model::Host;
use termiux_ssh::{
    Credential, HostKeyError, HostKeyInfo, KeyboardInteractiveResponder, KnownHostsVerifier, NewHostPrompt, SshError,
    SshSession,
};
use termiux_store::Store;
use tokio::net::TcpListener;

const HOST_KEY_A: &str = include_str!("fixtures/host_key_a");
const HOST_KEY_B: &str = include_str!("fixtures/host_key_b");
const PASSWORD: &str = "hunter2";
const OTP: &str = "123456";

/// PAM-like server: no plain password auth, keyboard-interactive password then optional OTP.
struct TestServer {
    otp: bool,
    step: usize,
}

impl server::Handler for TestServer {
    type Error = russh::Error;

    async fn auth_password(&mut self, _: &str, _: &str) -> Result<Auth, Self::Error> {
        Ok(Auth::Reject {
            proceed_with_methods: Some(MethodSet::from(&[MethodKind::KeyboardInteractive][..])),
            partial_success: false,
        })
    }

    async fn auth_keyboard_interactive<'a>(
        &'a mut self,
        _: &str,
        _: &str,
        response: Option<Response<'a>>,
    ) -> Result<Auth, Self::Error> {
        let answer = response.and_then(|mut r| r.next()).map(|b| String::from_utf8_lossy(&b).into_owned());
        let reject = Auth::Reject { proceed_with_methods: None, partial_success: false };
        let prompt = |text: &'static str, echo| Auth::Partial {
            name: Cow::Borrowed(""),
            instructions: Cow::Borrowed(""),
            prompts: Cow::Owned(vec![(Cow::Borrowed(text), echo)]),
        };
        self.step += 1;
        Ok(match (self.step, answer.as_deref()) {
            (1, None) => prompt("Password: ", false),
            (2, Some(PASSWORD)) if self.otp => prompt("Verification code: ", true),
            (2, Some(PASSWORD)) => Auth::Accept,
            (3, Some(OTP)) => Auth::Accept,
            _ => reject,
        })
    }
}

async fn spawn_server(host_key: &str, otp: bool) -> u16 {
    let config = Arc::new(server::Config {
        keys: vec![decode_secret_key(host_key, None).unwrap()],
        methods: MethodSet::from(&[MethodKind::Password, MethodKind::KeyboardInteractive][..]),
        auth_rejection_time: std::time::Duration::from_millis(10),
        ..Default::default()
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            let session = server::run_stream(config.clone(), socket, TestServer { otp, step: 0 });
            tokio::spawn(async move {
                if let Ok(s) = session.await {
                    let _ = s.await;
                }
            });
        }
    });
    port
}

fn host(port: u16) -> Host {
    let mut host = Host::new("test", "127.0.0.1", "tester");
    host.port = port;
    host
}

/// Records prompts and answers with a fixed decision.
struct Prompt {
    accept: bool,
    seen: Mutex<Vec<HostKeyInfo>>,
}

impl NewHostPrompt for Prompt {
    fn confirm_new_host(&self, info: &HostKeyInfo) -> bool {
        self.seen.lock().unwrap().push(info.clone());
        self.accept
    }
}

fn verifier(store: &Arc<Store>, accept: bool) -> (Arc<KnownHostsVerifier>, Arc<Prompt>) {
    let prompt = Arc::new(Prompt { accept, seen: Mutex::new(Vec::new()) });
    (Arc::new(KnownHostsVerifier { store: store.clone(), prompt: prompt.clone() }), prompt)
}

#[tokio::test]
async fn password_falls_back_to_keyboard_interactive() {
    let port = spawn_server(HOST_KEY_A, false).await;
    let store = Arc::new(Store::open_in_memory().unwrap());
    let (v, _) = verifier(&store, true);
    SshSession::connect(&host(port), Credential::Password { password: PASSWORD.into(), fallback: None }, v.clone())
        .await
        .unwrap();

    let wrong =
        SshSession::connect(&host(port), Credential::Password { password: "nope".into(), fallback: None }, v).await;
    assert!(matches!(wrong, Err(SshError::AuthRejected)));
}

struct OtpResponder(AtomicUsize);

impl KeyboardInteractiveResponder for OtpResponder {
    fn respond(&self, _: &str, _: &str, prompts: &[(String, bool)]) -> Option<Vec<String>> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Some(
            prompts
                .iter()
                .map(|(text, _)| if text.starts_with("Password") { PASSWORD } else { OTP }.to_string())
                .collect(),
        )
    }
}

#[tokio::test]
async fn keyboard_interactive_multi_round() {
    let port = spawn_server(HOST_KEY_A, true).await;
    let store = Arc::new(Store::open_in_memory().unwrap());
    let (v, _) = verifier(&store, true);
    let responder = Arc::new(OtpResponder(AtomicUsize::new(0)));
    SshSession::connect(&host(port), Credential::KeyboardInteractive(responder.clone()), v).await.unwrap();
    assert_eq!(responder.0.load(Ordering::SeqCst), 2, "password + OTP rounds");
}

#[tokio::test]
async fn stored_password_then_otp_uses_fallback() {
    let port = spawn_server(HOST_KEY_A, true).await;
    let store = Arc::new(Store::open_in_memory().unwrap());
    let (v, _) = verifier(&store, true);
    let fallback = Arc::new(OtpResponder(AtomicUsize::new(0)));
    let credential = Credential::Password { password: PASSWORD.into(), fallback: Some(fallback.clone()) };
    SshSession::connect(&host(port), credential, v.clone()).await.unwrap();
    assert_eq!(fallback.0.load(Ordering::SeqCst), 1, "only the OTP round reaches the user");

    // Without a fallback the OTP round cannot be answered.
    let credential = Credential::Password { password: PASSWORD.into(), fallback: None };
    let result = SshSession::connect(&host(port), credential, v).await;
    assert!(matches!(result, Err(SshError::AuthRejected)));
}

struct Cancel;
impl KeyboardInteractiveResponder for Cancel {
    fn respond(&self, _: &str, _: &str, _: &[(String, bool)]) -> Option<Vec<String>> {
        None
    }
}

#[tokio::test]
async fn keyboard_interactive_cancel_is_rejection() {
    let port = spawn_server(HOST_KEY_A, true).await;
    let store = Arc::new(Store::open_in_memory().unwrap());
    let (v, _) = verifier(&store, true);
    let result = SshSession::connect(&host(port), Credential::KeyboardInteractive(Arc::new(Cancel)), v).await;
    assert!(matches!(result, Err(SshError::AuthRejected)));
}

#[tokio::test]
async fn known_hosts_trust_on_first_use_then_detect_change() {
    let port = spawn_server(HOST_KEY_A, false).await;
    let store = Arc::new(Store::open_in_memory().unwrap());

    // Declined prompt: nothing stored, connection refused.
    let (v, prompt) = verifier(&store, false);
    let refused =
        SshSession::connect(&host(port), Credential::Password { password: PASSWORD.into(), fallback: None }, v).await;
    assert!(matches!(refused, Err(SshError::HostKey(HostKeyError::NotTrusted { .. }))));
    assert_eq!(prompt.seen.lock().unwrap().len(), 1);
    assert!(store.known_host_keys("127.0.0.1", port).unwrap().is_empty());

    // Accepted prompt: key stored with the fingerprint the user saw.
    let (v, prompt) = verifier(&store, true);
    SshSession::connect(&host(port), Credential::Password { password: PASSWORD.into(), fallback: None }, v.clone())
        .await
        .unwrap();
    let seen = prompt.seen.lock().unwrap()[0].clone();
    let expected = PrivateKey::from_openssh(HOST_KEY_A).unwrap().public_key().fingerprint(Default::default());
    assert_eq!(seen.fingerprint, expected.to_string());
    assert_eq!(seen.algorithm, "ssh-ed25519");

    // Second connection: trusted silently.
    SshSession::connect(&host(port), Credential::Password { password: PASSWORD.into(), fallback: None }, v.clone())
        .await
        .unwrap();
    assert_eq!(prompt.seen.lock().unwrap().len(), 1);

    // Same address now presents a different key: hard failure, no prompt.
    let impostor = spawn_server(HOST_KEY_B, false).await;
    let fp_a = store.known_host_keys("127.0.0.1", port).unwrap()[0].clone();
    store.trust_host_key("127.0.0.1", impostor, &fp_a).unwrap();
    let mitm =
        SshSession::connect(&host(impostor), Credential::Password { password: PASSWORD.into(), fallback: None }, v)
            .await;
    match mitm {
        Err(SshError::HostKey(HostKeyError::Changed { previous_fingerprint, .. })) => {
            assert_eq!(previous_fingerprint, fp_a.fingerprint)
        }
        other => panic!("expected host key change error, got {:?}", other.err()),
    }
    assert_eq!(prompt.seen.lock().unwrap().len(), 1, "changed keys must never prompt");
}
