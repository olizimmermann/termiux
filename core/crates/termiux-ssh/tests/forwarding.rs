//! Port forwarding (-L, -R, -D) and jump hosts against in-process russh servers.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use russh::keys::{PublicKey, decode_secret_key};
use russh::server::{self, Auth, ChannelOpenHandle, Msg, Session};
use russh::{Channel, MethodKind, MethodSet};
use termiux_model::Host;
use termiux_ssh::{Credential, HostKeyError, HostKeyVerifier, SshSession, forward};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const HOST_KEY: &str = include_str!("fixtures/host_key_a");

#[derive(Clone)]
struct Server {
    logins: Arc<AtomicUsize>,
}

impl server::Handler for Server {
    type Error = russh::Error;

    async fn auth_password(&mut self, _: &str, password: &str) -> Result<Auth, Self::Error> {
        if password == "pw" {
            self.logins.fetch_add(1, Ordering::SeqCst);
            Ok(Auth::Accept)
        } else {
            Ok(Auth::reject())
        }
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<Msg>,
        host: &str,
        port: u32,
        _: &str,
        _: u32,
        reply: ChannelOpenHandle,
        _: &mut Session,
    ) -> Result<(), Self::Error> {
        let Ok(mut target) = TcpStream::connect((host, port as u16)).await else {
            reply.reject(russh::ChannelOpenFailure::ConnectFailed).await;
            return Ok(());
        };
        reply.accept().await;
        tokio::spawn(async move {
            let mut stream = channel.into_stream();
            let _ = tokio::io::copy_bidirectional(&mut target, &mut stream).await;
        });
        Ok(())
    }

    async fn tcpip_forward(
        &mut self,
        address: &str,
        port: &mut u32,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        let Ok(listener) = TcpListener::bind((address, *port as u16)).await else { return Ok(false) };
        *port = listener.local_addr().unwrap().port().into();
        let (handle, address, bound) = (session.handle(), address.to_string(), *port);
        tokio::spawn(async move {
            while let Ok((mut stream, peer)) = listener.accept().await {
                let Ok(channel) = handle
                    .channel_open_forwarded_tcpip(address.clone(), bound, peer.ip().to_string(), peer.port().into())
                    .await
                else {
                    continue;
                };
                tokio::spawn(async move {
                    let mut remote = channel.into_stream();
                    let _ = tokio::io::copy_bidirectional(&mut stream, &mut remote).await;
                });
            }
        });
        Ok(true)
    }
}

async fn spawn_server() -> (u16, Arc<AtomicUsize>) {
    let config = Arc::new(server::Config {
        keys: vec![decode_secret_key(HOST_KEY, None).unwrap()],
        methods: MethodSet::from(&[MethodKind::Password][..]),
        auth_rejection_time: std::time::Duration::from_millis(10),
        ..Default::default()
    });
    let logins = Arc::new(AtomicUsize::new(0));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = Server { logins: logins.clone() };
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            let session = server::run_stream(config.clone(), socket, server.clone());
            tokio::spawn(async move {
                if let Ok(s) = session.await {
                    let _ = s.await;
                }
            });
        }
    });
    (port, logins)
}

/// TCP server that answers each line with "echo: <line>".
async fn spawn_echo() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 256];
                while let Ok(n) = stream.read(&mut buf).await {
                    if n == 0 {
                        break;
                    }
                    let reply = [b"echo: ".as_slice(), &buf[..n]].concat();
                    if stream.write_all(&reply).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    port
}

/// Records host-key checks so tests can see which hosts were verified.
#[derive(Default)]
struct RecordingVerifier(std::sync::Mutex<Vec<(String, u16)>>);

impl HostKeyVerifier for RecordingVerifier {
    fn verify(&self, host: &str, port: u16, _: &PublicKey) -> Result<(), HostKeyError> {
        self.0.lock().unwrap().push((host.to_string(), port));
        Ok(())
    }
}

fn host(port: u16) -> Host {
    let mut host = Host::new("t", "127.0.0.1", "tester");
    host.port = port;
    host
}

fn password() -> Credential {
    Credential::Password { password: "pw".into(), fallback: None }
}

async fn connect(port: u16) -> Arc<SshSession> {
    Arc::new(SshSession::connect(&host(port), password(), Arc::new(RecordingVerifier::default())).await.unwrap())
}

async fn round_trip(stream: &mut TcpStream, text: &str) -> String {
    stream.write_all(text.as_bytes()).await.unwrap();
    let mut buf = vec![0u8; 256];
    let n = tokio::time::timeout(std::time::Duration::from_secs(5), stream.read(&mut buf)).await.unwrap().unwrap();
    String::from_utf8_lossy(&buf[..n]).into_owned()
}

#[tokio::test]
async fn local_forward() {
    let (port, _) = spawn_server().await;
    let echo = spawn_echo().await;
    let session = connect(port).await;
    let fwd = forward::local(session, "127.0.0.1", 0, "127.0.0.1", echo).await.unwrap();
    let mut client = TcpStream::connect(("127.0.0.1", fwd.bound.1)).await.unwrap();
    assert_eq!(round_trip(&mut client, "hi").await, "echo: hi");

    // Stopping closes the listener.
    let bound = fwd.bound.1;
    fwd.stop().await;
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert!(TcpStream::connect(("127.0.0.1", bound)).await.is_err());
}

async fn socks_connect(proxy: u16, host: &str, port: u16) -> TcpStream {
    let mut s = TcpStream::connect(("127.0.0.1", proxy)).await.unwrap();
    s.write_all(&[5, 1, 0]).await.unwrap();
    let mut reply = [0u8; 2];
    s.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply, [5, 0]);
    let mut request = vec![5, 1, 0, 3, host.len() as u8];
    request.extend_from_slice(host.as_bytes());
    request.extend_from_slice(&port.to_be_bytes());
    s.write_all(&request).await.unwrap();
    let mut response = [0u8; 10];
    s.read_exact(&mut response).await.unwrap();
    assert_eq!(response[1], 0, "SOCKS request failed");
    s
}

#[tokio::test]
async fn dynamic_socks_forward() {
    let (port, _) = spawn_server().await;
    let echo = spawn_echo().await;
    let session = connect(port).await;
    let fwd = forward::dynamic(session, "127.0.0.1", 0).await.unwrap();
    let mut client = socks_connect(fwd.bound.1, "127.0.0.1", echo).await;
    assert_eq!(round_trip(&mut client, "via socks").await, "echo: via socks");
}

#[tokio::test]
async fn remote_forward() {
    let (port, _) = spawn_server().await;
    let echo = spawn_echo().await;
    let session = connect(port).await;
    let fwd = forward::remote(session, "127.0.0.1", 0, "127.0.0.1", echo).await.unwrap();
    assert_ne!(fwd.bound.1, 0, "server assigned a port");
    // The "server" listens on this machine, so connect to it directly.
    let mut client = TcpStream::connect(("127.0.0.1", fwd.bound.1)).await.unwrap();
    assert_eq!(round_trip(&mut client, "back").await, "echo: back");
}

#[tokio::test]
async fn jump_host_chain() {
    let (jump_port, jump_logins) = spawn_server().await;
    let (target_port, target_logins) = spawn_server().await;
    let verifier = Arc::new(RecordingVerifier::default());

    let jump = Arc::new(SshSession::connect(&host(jump_port), password(), verifier.clone()).await.unwrap());
    let target =
        Arc::new(SshSession::connect_via(jump, &host(target_port), password(), verifier.clone()).await.unwrap());
    assert_eq!(jump_logins.load(Ordering::SeqCst), 1);
    assert_eq!(target_logins.load(Ordering::SeqCst), 1);
    // Both hops had their host keys checked under their own address.
    assert_eq!(*verifier.0.lock().unwrap(), vec![("127.0.0.1".into(), jump_port), ("127.0.0.1".into(), target_port)]);

    // Forwards work through the tunnelled session too.
    let echo = spawn_echo().await;
    let fwd = forward::local(target, "127.0.0.1", 0, "127.0.0.1", echo).await.unwrap();
    let mut client = TcpStream::connect(("127.0.0.1", fwd.bound.1)).await.unwrap();
    assert_eq!(round_trip(&mut client, "two hops").await, "echo: two hops");
}

#[tokio::test]
async fn jump_to_unreachable_target_fails() {
    let (jump_port, _) = spawn_server().await;
    let jump = connect(jump_port).await;
    let closed = TcpListener::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap().port();
    let result = SshSession::connect_via(jump, &host(closed), password(), Arc::new(RecordingVerifier::default())).await;
    assert!(result.is_err());
}
