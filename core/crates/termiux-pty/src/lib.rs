//! Local shell sessions on a pseudo-terminal (macOS/Linux now, Windows ConPTY later).
//! Not available in sandboxed (App Store) builds.

use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::Mutex;

use portable_pty::{ChildKiller, CommandBuilder, MasterPty, PtySize, native_pty_system};

#[derive(Debug, thiserror::Error)]
pub enum PtyError {
    #[error("pty: {0}")]
    Pty(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

fn pty_err(e: impl std::fmt::Display) -> PtyError {
    PtyError::Pty(e.to_string())
}

#[derive(Debug, Clone, Default)]
pub struct ShellOptions {
    /// Program to run; defaults to the user's login shell.
    pub program: Option<String>,
    pub args: Vec<String>,
    /// Working directory; defaults to the home directory.
    pub cwd: Option<PathBuf>,
    pub env: Vec<(String, String)>,
    pub cols: u16,
    pub rows: u16,
}

pub struct LocalShell {
    master: Mutex<Box<dyn MasterPty + Send>>,
    writer: Mutex<Box<dyn Write + Send>>,
    killer: Mutex<Box<dyn ChildKiller + Send + Sync>>,
}

/// The user's login shell, falling back to /bin/zsh (macOS default).
pub fn default_shell() -> String {
    std::env::var("SHELL").ok().filter(|s| !s.is_empty()).unwrap_or_else(|| "/bin/zsh".into())
}

impl LocalShell {
    /// Starts the shell. Output is delivered from a dedicated reader thread; `on_exit`
    /// fires once with the exit code after the output stream ends.
    pub fn spawn(
        options: ShellOptions,
        on_output: impl Fn(&[u8]) + Send + 'static,
        on_exit: impl FnOnce(Option<u32>) + Send + 'static,
    ) -> Result<Self, PtyError> {
        let pair = native_pty_system().openpty(size(options.cols, options.rows)).map_err(pty_err)?;

        let (program, args) = match options.program {
            Some(p) => (p, options.args),
            // Login shell, like Terminal.app and iTerm2, so profile files are read.
            None => (default_shell(), vec!["-l".into()]),
        };
        let mut cmd = CommandBuilder::new(program);
        cmd.args(args);
        let cwd = options.cwd.or_else(|| std::env::var_os("HOME").map(PathBuf::from));
        if let Some(cwd) = cwd {
            cmd.cwd(cwd);
        }
        cmd.env("TERM", "xterm-256color");
        cmd.env("COLORTERM", "truecolor");
        cmd.env("TERM_PROGRAM", "Termiux");
        cmd.env("TERM_PROGRAM_VERSION", env!("CARGO_PKG_VERSION"));
        // GUI apps on macOS start without a locale; without it shells mangle UTF-8.
        if std::env::var_os("LANG").is_none() {
            cmd.env("LANG", "en_US.UTF-8");
        }
        for (k, v) in options.env {
            cmd.env(k, v);
        }

        let mut child = pair.slave.spawn_command(cmd).map_err(pty_err)?;
        // Close our copy of the slave so EOF arrives when the child exits.
        drop(pair.slave);
        let mut reader = pair.master.try_clone_reader().map_err(pty_err)?;
        let writer = pair.master.take_writer().map_err(pty_err)?;
        let killer = child.clone_killer();

        std::thread::Builder::new().name("termiux-pty-reader".into()).spawn(move || {
            let mut buf = vec![0u8; 64 * 1024];
            loop {
                match reader.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => on_output(&buf[..n]),
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(_) => break,
                }
            }
            on_exit(child.wait().ok().map(|status| status.exit_code()));
        })?;

        Ok(Self { master: Mutex::new(pair.master), writer: Mutex::new(writer), killer: Mutex::new(killer) })
    }

    pub fn write(&self, bytes: &[u8]) -> Result<(), PtyError> {
        let mut w = self.writer.lock().unwrap_or_else(|e| e.into_inner());
        w.write_all(bytes)?;
        w.flush()?;
        Ok(())
    }

    pub fn resize(&self, cols: u16, rows: u16) -> Result<(), PtyError> {
        self.master.lock().unwrap_or_else(|e| e.into_inner()).resize(size(cols, rows)).map_err(pty_err)
    }

    pub fn kill(&self) -> Result<(), PtyError> {
        self.killer.lock().unwrap_or_else(|e| e.into_inner()).kill()?;
        Ok(())
    }
}

impl Drop for LocalShell {
    fn drop(&mut self) {
        let _ = self.kill();
    }
}

fn size(cols: u16, rows: u16) -> PtySize {
    PtySize { cols: cols.max(1), rows: rows.max(1), pixel_width: 0, pixel_height: 0 }
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use super::*;

    fn run(options: ShellOptions, input: &[u8]) -> (String, Option<u32>) {
        let out = Arc::new(Mutex::new(Vec::new()));
        let sink = out.clone();
        let (tx, rx) = mpsc::channel();
        let shell = LocalShell::spawn(
            options,
            move |b| sink.lock().unwrap().extend_from_slice(b),
            move |code| tx.send(code).unwrap(),
        )
        .unwrap();
        shell.write(input).unwrap();
        let code = rx.recv_timeout(Duration::from_secs(10)).expect("shell did not exit");
        (String::from_utf8_lossy(&out.lock().unwrap()).into_owned(), code)
    }

    fn sh(cols: u16, rows: u16) -> ShellOptions {
        ShellOptions { program: Some("/bin/sh".into()), cols, rows, ..Default::default() }
    }

    #[test]
    fn runs_commands_and_reports_exit_code() {
        let (out, code) = run(sh(80, 24), b"echo pty-$((6*7)); exit 3\n");
        assert!(out.contains("pty-42"), "{out}");
        assert_eq!(code, Some(3));
    }

    #[test]
    fn terminal_env_and_size() {
        let (out, _) = run(sh(132, 43), b"echo \"$TERM|$COLORTERM|$TERM_PROGRAM\"; stty size; exit\n");
        assert!(out.contains("xterm-256color|truecolor|Termiux"), "{out}");
        assert!(out.contains("43 132"), "{out}");
    }

    #[test]
    fn resize_is_visible_to_child() {
        let out = Arc::new(Mutex::new(Vec::new()));
        let sink = out.clone();
        let (tx, rx) = mpsc::channel();
        let shell = LocalShell::spawn(
            sh(80, 24),
            move |b| sink.lock().unwrap().extend_from_slice(b),
            move |c| tx.send(c).unwrap(),
        )
        .unwrap();
        shell.resize(100, 30).unwrap();
        shell.write(b"stty size; exit\n").unwrap();
        rx.recv_timeout(Duration::from_secs(10)).unwrap();
        let out = String::from_utf8_lossy(&out.lock().unwrap()).into_owned();
        assert!(out.contains("30 100"), "{out}");
    }

    #[test]
    fn kill_ends_session() {
        let (tx, rx) = mpsc::channel();
        let shell = LocalShell::spawn(sh(80, 24), |_| {}, move |c| tx.send(c).unwrap()).unwrap();
        shell.kill().unwrap();
        rx.recv_timeout(Duration::from_secs(10)).expect("exit after kill");
    }
}
