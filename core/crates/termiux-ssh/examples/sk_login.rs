//! Manual FIDO2 check with a real security key.
//!   cargo run -p termiux-ssh --example sk_login -- generate <out-file>
//!   cargo run -p termiux-ssh --example sk_login -- login <key-file> <host> <port> <user>

use std::sync::Arc;

use russh::keys::PublicKey;
use termiux_model::Host;
use termiux_ssh::{Credential, HostKeyError, HostKeyVerifier, SshSession};

struct AcceptAll;
impl HostKeyVerifier for AcceptAll {
    fn verify(&self, _: &str, _: u16, _: &PublicKey) -> Result<(), HostKeyError> {
        Ok(())
    }
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    // Generating needs the FIDO2 PIN on most keys; login usually just needs a touch.
    let pin = match args.first().map(String::as_str) {
        Some("generate") => rpassword::prompt_password("FIDO2 PIN (empty if none): ").ok().filter(|p| !p.is_empty()),
        _ => None,
    };
    match args.first().map(String::as_str) {
        Some("generate") => {
            println!("Touch your security key…");
            let key = termiux_fido::generate_ed25519(termiux_fido::DEFAULT_APPLICATION, "termiux-sk", pin.as_deref())
                .expect("generate");
            std::fs::write(&args[1], key.to_openssh().unwrap()).unwrap();
            let public = key.public_key.to_openssh().unwrap();
            std::fs::write(format!("{}.pub", args[1]), format!("{public}\n")).unwrap();
            println!("{public}");
        }
        Some("login") => {
            let key = termiux_fido::SkKey::from_openssh(&std::fs::read_to_string(&args[1]).unwrap()).unwrap();
            let mut host = Host::new("sk", &args[2], &args[4]);
            host.port = args[3].parse().unwrap();
            println!("Touch your security key…");
            let session = SshSession::connect(&host, Credential::SecurityKey { key, pin }, Arc::new(AcceptAll))
                .await
                .expect("login");
            println!("Authenticated with security key.");
            session.disconnect().await.unwrap();
        }
        _ => eprintln!("usage: sk_login generate <out> | login <key> <host> <port> <user>"),
    }
}
