//! Credential resolution, key import and local sessions. Fixture keys are throwaway.

use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use russh::keys::ssh_key::public::{Ed25519PublicKey, KeyData, SkEd25519};
use termiux_model::{AuthMethod, EndReason, Host, KeyStorage, SessionEnd};
use termiux_pty::ShellOptions;
use termiux_session::{Core, Interaction, SessionError, TerminalSink};
use termiux_ssh::{Credential, HostKeyInfo};
use termiux_store::{MemorySecretStore, Store};

const PLAIN: &str = include_str!("fixtures/ed25519_plain");
const ENCRYPTED: &str = include_str!("fixtures/ed25519_encrypted");

fn core() -> Core {
    Core {
        store: Arc::new(Store::open_in_memory().unwrap()),
        secrets: Arc::new(MemorySecretStore::default()),
        platform: None,
        agent_socket: None,
    }
}

/// Scripted UI: answers secrets from a queue and records what was asked.
#[derive(Default)]
struct Ui {
    answers: Mutex<Vec<String>>,
    asked: Mutex<Vec<String>>,
}

impl Interaction for Ui {
    fn confirm_new_host(&self, _: &HostKeyInfo) -> bool {
        true
    }
    fn keyboard_interactive(&self, _: &str, _: &str, _: &[(String, bool)]) -> Option<Vec<String>> {
        None
    }
    fn ask_secret(&self, title: &str, _: &str) -> Option<String> {
        self.asked.lock().unwrap().push(title.to_string());
        self.answers.lock().unwrap().pop()
    }
}

fn ui(answers: &[&str]) -> (Arc<Ui>, Arc<dyn Interaction>) {
    let ui =
        Arc::new(Ui { answers: Mutex::new(answers.iter().map(|s| s.to_string()).collect()), ..Default::default() });
    (ui.clone(), ui)
}

#[test]
fn stored_password_is_resolved_without_prompting() {
    let core = core();
    let mut host = Host::new("h", "example.com", "me");
    core.set_host_password(&mut host, Some("s3cret")).unwrap();
    let (probe, ui) = ui(&[]);
    match core.resolve_credential(&core.store.host(host.id).unwrap().unwrap(), &ui).unwrap() {
        Credential::Password { password, fallback } => {
            assert_eq!(password, "s3cret");
            assert!(fallback.is_some());
        }
        _ => panic!("expected password"),
    }
    assert!(probe.asked.lock().unwrap().is_empty());
}

#[test]
fn replacing_password_deletes_old_secret() {
    let core = core();
    let mut host = Host::new("h", "example.com", "me");
    core.set_host_password(&mut host, Some("one")).unwrap();
    let AuthMethod::Password { secret: Some(old) } = host.auth.clone() else { panic!() };
    core.set_host_password(&mut host, None).unwrap();
    assert!(core.secrets.get(&old).unwrap().is_none());
    assert_eq!(host.auth, AuthMethod::Password { secret: None });
}

#[test]
fn missing_password_prompts_and_cancel_aborts() {
    let core = core();
    let host = Host::new("h", "example.com", "me");
    let (_, answering) = ui(&["typed"]);
    assert!(matches!(
        core.resolve_credential(&host, &answering).unwrap(),
        Credential::Password { password, .. } if password == "typed"
    ));
    let (_, cancelling) = ui(&[]);
    assert!(matches!(core.resolve_credential(&host, &cancelling), Err(SessionError::Cancelled)));
}

#[test]
fn import_plain_key_and_resolve() {
    let core = core();
    let key = core.import_key("laptop", PLAIN, None).unwrap();
    assert!(key.public_key.starts_with("ssh-ed25519 "));
    assert!(matches!(key.storage, KeyStorage::Software { passphrase: None, .. }));
    // The database never contains private key material.
    let stored = core.store.key(key.id).unwrap().unwrap();
    assert!(!format!("{stored:?}").contains("PRIVATE KEY"));

    let mut host = Host::new("h", "example.com", "me");
    host.auth = AuthMethod::Key { key_id: key.id };
    let (_, ui) = ui(&[]);
    match core.resolve_credential(&host, &ui).unwrap() {
        Credential::PrivateKey { openssh, passphrase } => {
            assert!(openssh.contains("OPENSSH PRIVATE KEY"));
            assert_eq!(passphrase, None);
        }
        _ => panic!("expected private key"),
    }
}

#[test]
fn import_encrypted_key_validates_passphrase() {
    let core = core();
    assert!(matches!(core.import_key("k", ENCRYPTED, None), Err(SessionError::InvalidKey(_))));
    assert!(matches!(core.import_key("k", ENCRYPTED, Some("wrong")), Err(SessionError::InvalidKey(_))));
    let key = core.import_key("k", ENCRYPTED, Some("correct horse")).unwrap();
    let KeyStorage::Software { passphrase: Some(_), .. } = &key.storage else { panic!("passphrase not stored") };

    let mut host = Host::new("h", "example.com", "me");
    host.auth = AuthMethod::Key { key_id: key.id };
    let (_, ui) = ui(&[]);
    let Credential::PrivateKey { passphrase, .. } = core.resolve_credential(&host, &ui).unwrap() else { panic!() };
    assert_eq!(passphrase.as_deref(), Some("correct horse"));

    core.delete_key(key.id).unwrap();
    assert!(core.store.key(key.id).unwrap().is_none());
}

#[test]
fn import_security_key_file() {
    let public = SkEd25519::new(Ed25519PublicKey([7u8; 32]), "ssh:");
    let mut public_key = russh::keys::PublicKey::from(KeyData::SkEd25519(public));
    public_key.set_comment("yubikey");
    let sk = termiux_fido::SkKey { application: "ssh:".into(), credential_id: vec![1, 2, 3, 4], public_key };
    let file = sk.to_openssh().unwrap();

    let core = core();
    let key = core.import_key("yubikey", &file, None).unwrap();
    assert!(key.public_key.starts_with("sk-ssh-ed25519@openssh.com "));
    assert!(matches!(key.storage, KeyStorage::SecurityKey { .. }));

    let mut host = Host::new("h", "example.com", "me");
    host.auth = AuthMethod::Key { key_id: key.id };
    let (_, ui) = ui(&[]);
    let Credential::SecurityKey { key: resolved, .. } = core.resolve_credential(&host, &ui).unwrap() else {
        panic!("expected security key")
    };
    assert_eq!(resolved.credential_id, vec![1, 2, 3, 4]);
}

struct Sink {
    output: Mutex<Vec<u8>>,
    ended: Mutex<Option<mpsc::Sender<SessionEnd>>>,
}

impl TerminalSink for Sink {
    fn output(&self, data: &[u8]) {
        self.output.lock().unwrap().extend_from_slice(data);
    }
    fn ended(&self, end: SessionEnd) {
        if let Some(tx) = self.ended.lock().unwrap().take() {
            tx.send(end).unwrap();
        }
    }
}

fn local(core: &Core) -> (termiux_session::TerminalSession, Arc<Sink>, mpsc::Receiver<SessionEnd>) {
    let (tx, rx) = mpsc::channel();
    let sink = Arc::new(Sink { output: Mutex::new(Vec::new()), ended: Mutex::new(Some(tx)) });
    let options = ShellOptions { program: Some("/bin/sh".into()), cols: 80, rows: 24, ..Default::default() };
    (core.open_local_shell(options, sink.clone()).unwrap(), sink, rx)
}

#[tokio::test]
async fn local_session_reports_exit_and_user_close() {
    let core = core();
    let (session, sink, ended) = local(&core);
    session.resize(90, 30);
    session.write(b"stty size; exit 5\n");
    let end = ended.recv_timeout(Duration::from_secs(10)).unwrap();
    assert_eq!(end, SessionEnd { exit_status: Some(5), reason: EndReason::Exited });
    assert!(String::from_utf8_lossy(&sink.output.lock().unwrap()).contains("30 90"));

    let (session, _, ended) = local(&core);
    session.close().await;
    assert_eq!(ended.recv_timeout(Duration::from_secs(10)).unwrap().reason, EndReason::UserClosed);
}

#[test]
fn generate_and_export_keys() {
    let core = core();
    let key = core.generate_key("work", termiux_keys::KeyType::Ed25519, Some("pw")).unwrap();
    assert!(key.public_key.starts_with("ssh-ed25519 "));
    let KeyStorage::Software { passphrase: Some(_), .. } = &key.storage else { panic!("passphrase not kept") };

    // Export without a passphrase decrypts with the stored one.
    let plain = core.export_private_key(key.id, None).unwrap();
    let parsed = russh::keys::PrivateKey::from_openssh(&plain).unwrap();
    assert!(!parsed.is_encrypted());
    assert_eq!(parsed.public_key().to_openssh().unwrap().split(' ').nth(1), key.public_key.split(' ').nth(1));

    let encrypted = core.export_private_key(key.id, Some("new")).unwrap();
    assert!(russh::keys::PrivateKey::from_openssh(&encrypted).unwrap().is_encrypted());
}

#[test]
fn platform_keys_resolve_to_external_signer() {
    let core = core();
    let public =
        termiux_keys::generate(termiux_keys::KeyType::EcdsaP256, "").unwrap().public_key().to_openssh().unwrap();
    let key = core.add_platform_key("Touch ID", &public, KeyStorage::SecureEnclave { tag: "t".into() }).unwrap();
    assert!(key.public_key.ends_with(" Touch ID"));
    assert!(matches!(core.export_private_key(key.id, None), Err(SessionError::Unsupported(_))));

    let mut host = Host::new("h", "example.com", "me");
    host.auth = AuthMethod::Key { key_id: key.id };
    let (_, ui) = ui(&[]);
    // No platform signer on this "device".
    assert!(matches!(core.resolve_credential(&host, &ui), Err(SessionError::Unsupported(_))));
}

struct NullSink;
impl TerminalSink for NullSink {
    fn output(&self, _: &[u8]) {}
    fn ended(&self, _: SessionEnd) {}
}

#[tokio::test]
async fn jump_host_misconfiguration_fails_early() {
    let core = core();
    let (_, ui) = ui(&[]);

    let mut looping = Host::new("loop", "example.invalid", "me");
    looping.jump_hosts = vec![looping.id];
    let result = core.connect(looping, 80, 24, ui.clone(), Arc::new(NullSink)).await;
    assert!(matches!(result, Err(SessionError::JumpLoop)));

    let mut dangling = Host::new("dangling", "example.invalid", "me");
    let missing = uuid::Uuid::new_v4();
    dangling.jump_hosts = vec![missing];
    let result = core.connect(dangling, 80, 24, ui, Arc::new(NullSink)).await;
    assert!(matches!(result, Err(SessionError::MissingJumpHost(id)) if id == missing));
}
