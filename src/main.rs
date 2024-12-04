#![recursion_limit = "1024"]

mod config;
mod network;
mod server;
mod logger;
mod exit;
mod privileges;

use std::{sync::mpsc::channel, thread};
use std::io::Write;

use config::get_config;
use network::{init_networking, process_network_commands};
use exit::block_exit_signals;
use privileges::require_root;
use anyhow::Result;

fn main() {
    if let Err(ref e) = run() {
        let stderr = &mut ::std::io::stderr();
        let errmsg = "Error writing to stderr";

        writeln!(stderr, "\x1B[1;31mError: {}\x1B[0m", e).expect(errmsg);

    }
}

fn run() -> Result<()> {
    block_exit_signals()?;

    logger::init();

    let config = get_config();

    //require_root()?;

    init_networking(&config)?;

    let (exit_tx, exit_rx) = channel();

    thread::spawn(move || {
        process_network_commands(&config, &exit_tx);
    });

    match exit_rx.recv() {
        Ok(result) => if let Err(reason) = result {
            return Err(reason);
        },
        Err(e) => {
            return Err(e.into());
        },
    }

    Ok(())
}
