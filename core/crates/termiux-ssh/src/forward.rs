//! Port forwarding over an SSH session: local (-L), remote (-R) and dynamic SOCKS5 (-D).
//! Each forward runs until its [`Forward`] handle is stopped or dropped.

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

use crate::{SshError, SshSession};

/// A running forward. Stops when dropped.
pub struct Forward {
    /// Where it listens: the local address for -L/-D, the server-side address for -R.
    pub bound: (String, u16),
    task: Option<JoinHandle<()>>,
    remote: Option<(Arc<SshSession>, String, u32)>,
}

impl Forward {
    pub async fn stop(mut self) {
        if let Some((session, host, port)) = self.remote.take() {
            let _ = session.handle.cancel_tcpip_forward(host.clone(), port).await;
            session.remote_forwards.lock().ok().map(|mut f| f.remove(&(host, port)));
        }
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

impl Drop for Forward {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
        if let Some((session, host, port)) = self.remote.take() {
            session.remote_forwards.lock().ok().map(|mut f| f.remove(&(host.clone(), port)));
            tokio::spawn(async move {
                let _ = session.handle.cancel_tcpip_forward(host, port).await;
            });
        }
    }
}

async fn bind(host: &str, port: u16) -> Result<(TcpListener, (String, u16)), SshError> {
    let listener =
        TcpListener::bind((host, port)).await.map_err(|e| SshError::Forward(format!("{host}:{port}: {e}")))?;
    let addr = listener.local_addr().map_err(|e| SshError::Forward(e.to_string()))?;
    Ok((listener, (addr.ip().to_string(), addr.port())))
}

/// Pipes a local connection through a direct-tcpip channel to `target`.
async fn tunnel(session: &SshSession, mut local: TcpStream, peer: SocketAddr, target: (String, u16)) {
    let channel = session
        .handle
        .channel_open_direct_tcpip(target.0, target.1.into(), peer.ip().to_string(), peer.port().into())
        .await;
    if let Ok(channel) = channel {
        let mut remote = channel.into_stream();
        let _ = tokio::io::copy_bidirectional(&mut local, &mut remote).await;
    }
}

/// -L: listen on `bind`, connect to `target` from the server.
pub async fn local(
    session: Arc<SshSession>,
    bind_host: &str,
    bind_port: u16,
    target_host: &str,
    target_port: u16,
) -> Result<Forward, SshError> {
    let (listener, bound) = bind(bind_host, bind_port).await?;
    let target = (target_host.to_string(), target_port);
    let task = tokio::spawn(async move {
        while let Ok((stream, peer)) = listener.accept().await {
            let (session, target) = (session.clone(), target.clone());
            tokio::spawn(async move { tunnel(&session, stream, peer, target).await });
        }
    });
    Ok(Forward { bound, task: Some(task), remote: None })
}

/// -D: a SOCKS5 proxy on `bind`; each CONNECT goes out from the server.
pub async fn dynamic(session: Arc<SshSession>, bind_host: &str, bind_port: u16) -> Result<Forward, SshError> {
    let (listener, bound) = bind(bind_host, bind_port).await?;
    let task = tokio::spawn(async move {
        while let Ok((mut stream, peer)) = listener.accept().await {
            let session = session.clone();
            tokio::spawn(async move {
                if let Ok(target) = socks5_handshake(&mut stream).await {
                    tunnel(&session, stream, peer, target).await;
                }
            });
        }
    });
    Ok(Forward { bound, task: Some(task), remote: None })
}

/// -R: the server listens on `bind`; connections are forwarded to `target` from here.
/// `bind_port` 0 lets the server choose; the chosen port is in `Forward::bound`.
pub async fn remote(
    session: Arc<SshSession>,
    bind_host: &str,
    bind_port: u16,
    target_host: &str,
    target_port: u16,
) -> Result<Forward, SshError> {
    let assigned = session.handle.tcpip_forward(bind_host, bind_port.into()).await?;
    let port = if bind_port == 0 { assigned } else { bind_port.into() };
    session
        .remote_forwards
        .lock()
        .map_err(|_| SshError::Forward("lock poisoned".into()))?
        .insert((bind_host.to_string(), port), (target_host.to_string(), target_port));
    Ok(Forward {
        bound: (bind_host.to_string(), port as u16),
        task: None,
        remote: Some((session, bind_host.to_string(), port)),
    })
}

/// Minimal SOCKS5 server side: no authentication, CONNECT only. Returns the target.
async fn socks5_handshake(stream: &mut TcpStream) -> std::io::Result<(String, u16)> {
    let invalid = |m: &str| std::io::Error::new(std::io::ErrorKind::InvalidData, m.to_string());
    let mut head = [0u8; 2];
    stream.read_exact(&mut head).await?;
    if head[0] != 5 {
        return Err(invalid("not SOCKS5"));
    }
    let mut methods = vec![0u8; head[1] as usize];
    stream.read_exact(&mut methods).await?;
    if !methods.contains(&0) {
        stream.write_all(&[5, 0xff]).await?;
        return Err(invalid("no acceptable auth method"));
    }
    stream.write_all(&[5, 0]).await?;

    let mut request = [0u8; 4];
    stream.read_exact(&mut request).await?;
    let [5, command, _, address_type] = request else { return Err(invalid("bad request")) };
    let host = match address_type {
        1 => {
            let mut ip = [0u8; 4];
            stream.read_exact(&mut ip).await?;
            std::net::Ipv4Addr::from(ip).to_string()
        }
        3 => {
            let len = stream.read_u8().await? as usize;
            let mut name = vec![0u8; len];
            stream.read_exact(&mut name).await?;
            String::from_utf8(name).map_err(|_| invalid("bad host name"))?
        }
        4 => {
            let mut ip = [0u8; 16];
            stream.read_exact(&mut ip).await?;
            std::net::Ipv6Addr::from(ip).to_string()
        }
        _ => return Err(invalid("bad address type")),
    };
    let port = stream.read_u16().await?;
    if command != 1 {
        // Only CONNECT; reply "command not supported".
        stream.write_all(&[5, 7, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
        return Err(invalid("unsupported command"));
    }
    // Success; the bound address is not meaningful for a tunnel.
    stream.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
    Ok((host, port))
}
