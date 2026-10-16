//! SFTP file browsing and transfers on top of any SSH channel stream.
//!
//! Transfers copy whole files or directory trees with progress reporting and
//! cancellation; a cancelled or failed transfer removes the partial file it was writing.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use russh_sftp::client::SftpSession;
use russh_sftp::protocol::FileType;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[derive(Debug, thiserror::Error)]
pub enum SftpError {
    #[error("sftp: {0}")]
    Sftp(#[from] russh_sftp::client::error::Error),
    #[error("{path}: {source}")]
    Local { path: PathBuf, source: std::io::Error },
    #[error("cancelled")]
    Cancelled,
    #[error("{0} already exists")]
    Exists(String),
}

type Result<T> = std::result::Result<T, SftpError>;

fn local_err(path: &Path) -> impl FnOnce(std::io::Error) -> SftpError + '_ {
    move |source| SftpError::Local { path: path.to_path_buf(), source }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    File,
    Dir,
    Symlink,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub name: String,
    pub path: String,
    pub kind: EntryKind,
    pub size: u64,
    /// Seconds since the Unix epoch.
    pub modified: Option<u32>,
    /// Unix mode bits (including the file type bits).
    pub permissions: Option<u32>,
}

/// Progress of one transfer job (a file or a whole directory tree).
pub struct Progress<'a> {
    /// Called with (bytes done, bytes total) as data moves.
    pub report: &'a (dyn Fn(u64, u64) + Send + Sync),
    pub cancel: &'a AtomicBool,
}

struct Counter<'a> {
    progress: &'a Progress<'a>,
    done: u64,
    total: u64,
}

impl Counter<'_> {
    fn add(&mut self, n: u64) -> Result<()> {
        self.done += n;
        (self.progress.report)(self.done, self.total);
        if self.progress.cancel.load(Ordering::Relaxed) { Err(SftpError::Cancelled) } else { Ok(()) }
    }
}

const CHUNK: usize = 256 * 1024;

/// Remote paths always use `/`.
pub fn join(dir: &str, name: &str) -> String {
    if dir.ends_with('/') { format!("{dir}{name}") } else { format!("{dir}/{name}") }
}

pub fn parent(path: &str) -> String {
    match path.trim_end_matches('/').rsplit_once('/') {
        Some(("", _)) | None => "/".into(),
        Some((parent, _)) => parent.into(),
    }
}

pub struct Sftp {
    session: SftpSession,
}

impl Sftp {
    /// Starts the SFTP protocol on a stream (an SSH "sftp" subsystem channel).
    pub async fn new<S>(stream: S) -> Result<Self>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        Ok(Self { session: SftpSession::new(stream).await? })
    }

    /// Absolute path of the login directory.
    pub async fn home(&self) -> Result<String> {
        Ok(self.session.canonicalize(".").await?)
    }

    pub async fn canonicalize(&self, path: &str) -> Result<String> {
        Ok(self.session.canonicalize(path).await?)
    }

    /// Directory contents without `.`/`..`: folders first, then by name (case-insensitive).
    pub async fn list(&self, path: &str) -> Result<Vec<Entry>> {
        let mut entries: Vec<Entry> = self
            .session
            .read_dir(path)
            .await?
            .filter(|e| e.file_name() != "." && e.file_name() != "..")
            .map(|e| {
                let meta = e.metadata();
                Entry {
                    path: join(path, &e.file_name()),
                    name: e.file_name(),
                    kind: kind(e.file_type()),
                    size: meta.size.unwrap_or(0),
                    modified: meta.mtime,
                    permissions: meta.permissions,
                }
            })
            .collect();
        entries.sort_by(|a, b| {
            (a.kind != EntryKind::Dir)
                .cmp(&(b.kind != EntryKind::Dir))
                .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
        });
        Ok(entries)
    }

    pub async fn mkdir(&self, path: &str) -> Result<()> {
        Ok(self.session.create_dir(path).await?)
    }

    pub async fn rename(&self, from: &str, to: &str) -> Result<()> {
        if self.session.try_exists(to).await? {
            return Err(SftpError::Exists(to.to_string()));
        }
        Ok(self.session.rename(from, to).await?)
    }

    /// Removes a file, or a directory with everything in it. Symlinks are removed, not followed.
    pub async fn remove(&self, path: &str) -> Result<()> {
        let meta = self.session.symlink_metadata(path).await?;
        if meta.file_type() == FileType::Dir {
            for entry in self.list(path).await? {
                Box::pin(self.remove(&entry.path)).await?;
            }
            Ok(self.session.remove_dir(path).await?)
        } else {
            Ok(self.session.remove_file(path).await?)
        }
    }

    /// Total bytes of regular files under `path` (the file itself if it is one).
    async fn remote_size(&self, path: &str) -> Result<u64> {
        let meta = self.session.metadata(path).await?;
        if meta.file_type() != FileType::Dir {
            return Ok(meta.size.unwrap_or(0));
        }
        let mut total = 0;
        for entry in self.list(path).await? {
            total += match entry.kind {
                EntryKind::Dir => Box::pin(self.remote_size(&entry.path)).await?,
                EntryKind::File => entry.size,
                _ => 0,
            };
        }
        Ok(total)
    }

    /// Downloads a file or directory tree to `local` (the destination path itself).
    pub async fn download(&self, remote: &str, local: &Path, progress: &Progress<'_>) -> Result<u64> {
        let total = self.remote_size(remote).await?;
        let mut counter = Counter { progress, done: 0, total };
        (progress.report)(0, total);
        self.download_inner(remote, local, &mut counter).await?;
        Ok(counter.done)
    }

    async fn download_inner(&self, remote: &str, local: &Path, counter: &mut Counter<'_>) -> Result<()> {
        if self.session.metadata(remote).await?.file_type() == FileType::Dir {
            tokio::fs::create_dir_all(local).await.map_err(local_err(local))?;
            for entry in self.list(remote).await? {
                if matches!(entry.kind, EntryKind::Dir | EntryKind::File) {
                    Box::pin(self.download_inner(&entry.path, &local.join(&entry.name), counter)).await?;
                }
            }
            return Ok(());
        }
        let result = async {
            let mut source = self.session.open(remote).await?;
            let mut target = tokio::fs::File::create(local).await.map_err(local_err(local))?;
            let mut buf = vec![0u8; CHUNK];
            loop {
                let n = source.read(&mut buf).await.map_err(local_err(local))?;
                if n == 0 {
                    break;
                }
                target.write_all(&buf[..n]).await.map_err(local_err(local))?;
                counter.add(n as u64)?;
            }
            target.flush().await.map_err(local_err(local))
        }
        .await;
        if result.is_err() {
            let _ = tokio::fs::remove_file(local).await;
        }
        result
    }

    /// Uploads a local file or directory tree to `remote` (the destination path itself).
    pub async fn upload(&self, local: &Path, remote: &str, progress: &Progress<'_>) -> Result<u64> {
        let total = local_size(local).await?;
        let mut counter = Counter { progress, done: 0, total };
        (progress.report)(0, total);
        self.upload_inner(local, remote, &mut counter).await?;
        Ok(counter.done)
    }

    async fn upload_inner(&self, local: &Path, remote: &str, counter: &mut Counter<'_>) -> Result<()> {
        let meta = tokio::fs::metadata(local).await.map_err(local_err(local))?;
        if meta.is_dir() {
            if !self.session.try_exists(remote).await? {
                self.session.create_dir(remote).await?;
            }
            let mut dir = tokio::fs::read_dir(local).await.map_err(local_err(local))?;
            let mut children = Vec::new();
            while let Some(entry) = dir.next_entry().await.map_err(local_err(local))? {
                children.push(entry.path());
            }
            children.sort();
            for child in children {
                let name = child.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
                Box::pin(self.upload_inner(&child, &join(remote, &name), counter)).await?;
            }
            return Ok(());
        }
        let result = async {
            let mut source = tokio::fs::File::open(local).await.map_err(local_err(local))?;
            let mut target = self.session.create(remote).await?;
            let mut buf = vec![0u8; CHUNK];
            loop {
                let n = source.read(&mut buf).await.map_err(local_err(local))?;
                if n == 0 {
                    break;
                }
                target.write_all(&buf[..n]).await.map_err(local_err(local))?;
                counter.add(n as u64)?;
            }
            target.shutdown().await.map_err(local_err(local))
        }
        .await;
        if result.is_err() {
            let _ = self.session.remove_file(remote).await;
        }
        result
    }
}

fn kind(file_type: FileType) -> EntryKind {
    match file_type {
        FileType::Dir => EntryKind::Dir,
        FileType::File => EntryKind::File,
        FileType::Symlink => EntryKind::Symlink,
        FileType::Other => EntryKind::Other,
    }
}

async fn local_size(path: &Path) -> Result<u64> {
    let meta = tokio::fs::metadata(path).await.map_err(local_err(path))?;
    if !meta.is_dir() {
        return Ok(meta.len());
    }
    let mut total = 0;
    let mut dir = tokio::fs::read_dir(path).await.map_err(local_err(path))?;
    while let Some(entry) = dir.next_entry().await.map_err(local_err(path))? {
        total += Box::pin(local_size(&entry.path())).await?;
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_helpers() {
        assert_eq!(join("/home/me", "a.txt"), "/home/me/a.txt");
        assert_eq!(join("/", "etc"), "/etc");
        assert_eq!(parent("/home/me/a.txt"), "/home/me");
        assert_eq!(parent("/home"), "/");
        assert_eq!(parent("/"), "/");
        assert_eq!(parent("/home/me/"), "/home");
    }
}
