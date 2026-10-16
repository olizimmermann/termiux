//! Runs against the system's OpenSSH `sftp-server` over stdin/stdout, in a temp directory.

use std::path::Path;
use std::process::Stdio;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use termiux_sftp::{EntryKind, Progress, Sftp, SftpError};

const SFTP_SERVER: &str = "/usr/libexec/sftp-server";

/// Starts sftp-server with `dir` as its working (home) directory.
async fn connect(dir: &Path) -> (Sftp, tokio::process::Child) {
    let mut child = tokio::process::Command::new(SFTP_SERVER)
        .current_dir(dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("sftp-server");
    let stream = tokio::io::join(child.stdout.take().unwrap(), child.stdin.take().unwrap());
    (Sftp::new(stream).await.unwrap(), child)
}

fn quiet() -> (impl Fn(u64, u64) + Send + Sync, AtomicBool) {
    (|_, _| {}, AtomicBool::new(false))
}

#[tokio::test]
async fn list_mkdir_rename_remove() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("b.txt"), "hello").unwrap();
    std::fs::write(dir.path().join("A.txt"), "x").unwrap();
    std::fs::create_dir(dir.path().join("zdir")).unwrap();
    let (sftp, _child) = connect(dir.path()).await;

    let home = sftp.home().await.unwrap();
    assert_eq!(Path::new(&home).canonicalize().unwrap(), dir.path().canonicalize().unwrap());

    let entries = sftp.list(&home).await.unwrap();
    let names: Vec<_> = entries.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(names, ["zdir", "A.txt", "b.txt"], "folders first, then case-insensitive");
    assert_eq!(entries[0].kind, EntryKind::Dir);
    assert_eq!(entries[2].size, 5);

    let new_dir = termiux_sftp::join(&home, "new");
    sftp.mkdir(&new_dir).await.unwrap();
    std::fs::write(dir.path().join("new/inner.txt"), "i").unwrap();
    let renamed = termiux_sftp::join(&home, "renamed");
    sftp.rename(&new_dir, &renamed).await.unwrap();
    assert!(dir.path().join("renamed/inner.txt").exists());

    // Renaming onto an existing name is refused instead of silently replacing it.
    let existing = termiux_sftp::join(&home, "b.txt");
    assert!(matches!(sftp.rename(&renamed, &existing).await, Err(SftpError::Exists(_))));

    sftp.remove(&renamed).await.unwrap();
    assert!(!dir.path().join("renamed").exists(), "directories are removed recursively");
}

#[tokio::test]
async fn upload_and_download_tree_with_progress() {
    let remote_root = tempfile::tempdir().unwrap();
    let local = tempfile::tempdir().unwrap();
    let source = local.path().join("project");
    std::fs::create_dir_all(source.join("src/nested")).unwrap();
    std::fs::write(source.join("README"), vec![b'r'; 300_000]).unwrap();
    std::fs::write(source.join("src/main.rs"), "fn main() {}").unwrap();
    std::fs::write(source.join("src/nested/data.bin"), (0..=255u8).cycle().take(700_000).collect::<Vec<_>>()).unwrap();
    let total = 300_000 + 12 + 700_000;

    let (sftp, _child) = connect(remote_root.path()).await;
    let home = sftp.home().await.unwrap();
    let seen = Mutex::new(Vec::new());
    let report = |done, all| seen.lock().unwrap().push((done, all));
    let cancel = AtomicBool::new(false);
    let progress = Progress { report: &report, cancel: &cancel };

    let remote = termiux_sftp::join(&home, "project");
    assert_eq!(sftp.upload(&source, &remote, &progress).await.unwrap(), total);
    {
        let seen = seen.lock().unwrap();
        assert_eq!(seen.first(), Some(&(0, total)));
        assert_eq!(seen.last(), Some(&(total, total)));
        assert!(seen.windows(2).all(|w| w[0].0 <= w[1].0), "progress only grows");
    }
    assert_eq!(
        std::fs::read(remote_root.path().join("project/src/nested/data.bin")).unwrap(),
        std::fs::read(source.join("src/nested/data.bin")).unwrap()
    );

    let back = local.path().join("copy");
    let (report, cancel) = quiet();
    let n = sftp.download(&remote, &back, &Progress { report: &report, cancel: &cancel }).await.unwrap();
    assert_eq!(n, total);
    assert_eq!(std::fs::read(back.join("README")).unwrap(), std::fs::read(source.join("README")).unwrap());
    assert_eq!(std::fs::read_to_string(back.join("src/main.rs")).unwrap(), "fn main() {}");
}

#[tokio::test]
async fn cancelled_transfers_leave_no_partial_files() {
    let remote_root = tempfile::tempdir().unwrap();
    let local = tempfile::tempdir().unwrap();
    let big = local.path().join("big.bin");
    std::fs::write(&big, vec![7u8; 4 * 1024 * 1024]).unwrap();
    let (sftp, _child) = connect(remote_root.path()).await;
    let home = sftp.home().await.unwrap();

    // Cancel as soon as the first chunk has moved.
    let cancel = AtomicBool::new(false);
    let report = |done: u64, _| {
        if done > 0 {
            cancel.store(true, Ordering::SeqCst);
        }
    };
    let progress = Progress { report: &report, cancel: &cancel };
    let remote = termiux_sftp::join(&home, "big.bin");
    assert!(matches!(sftp.upload(&big, &remote, &progress).await, Err(SftpError::Cancelled)));
    assert!(!remote_root.path().join("big.bin").exists(), "partial upload removed");

    std::fs::write(remote_root.path().join("big.bin"), vec![7u8; 4 * 1024 * 1024]).unwrap();
    cancel.store(false, Ordering::SeqCst);
    let target = local.path().join("down.bin");
    assert!(matches!(sftp.download(&remote, &target, &progress).await, Err(SftpError::Cancelled)));
    assert!(!target.exists(), "partial download removed");
}
