//! Starts the user's login shell, runs one command and prints the raw output.
use std::sync::mpsc;
use std::time::Duration;

use termiux_pty::{LocalShell, ShellOptions};

fn main() {
    let (tx, rx) = mpsc::channel();
    let shell = LocalShell::spawn(
        ShellOptions { cols: 80, rows: 24, ..Default::default() },
        |b| print!("{}", String::from_utf8_lossy(b)),
        move |c| tx.send(c).unwrap(),
    )
    .unwrap();
    shell.write(b"echo shell=$0 pwd=$PWD lang=$LANG; exit\n").unwrap();
    println!("\n[exit {:?}]", rx.recv_timeout(Duration::from_secs(15)).unwrap());
}
