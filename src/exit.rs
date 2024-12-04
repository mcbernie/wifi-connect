use std::sync::mpsc::Sender;
use anyhow::{Error, Result};
use log::info;
use nix::sys::signal::{SigSet, Signal::{SIGHUP, SIGINT, SIGQUIT, SIGTERM}};

pub type ExitResult = Result<()>;

pub fn exit(exit_tx: &Sender<ExitResult>, error: Error) {
    let _ = exit_tx.send(Err(error));
}

/// Block exit signals from the main thread with mask inherited by children
pub fn block_exit_signals() -> Result<()> {
    let mask = create_exit_sigmask();
    mask.thread_block()?;

    Ok(())
}

/// Trap exit signals from a signal handling thread
pub fn trap_exit_signals() -> Result<()> {
    let mask = create_exit_sigmask();

    let sig = mask.wait()?;

    info!("\nReceived {:?}", sig);

    Ok(())
}

fn create_exit_sigmask() -> SigSet {
    let mut mask = SigSet::empty();

    mask.add(SIGINT);
    mask.add(SIGQUIT);
    mask.add(SIGTERM);
    mask.add(SIGHUP);

    mask
}
