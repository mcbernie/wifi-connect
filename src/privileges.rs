use anyhow::{bail, Result};
use nix::unistd::Uid;


pub fn require_root() -> Result<()> {
    if !Uid::effective().is_root() {
        bail!("This program must be run as root")
    } else {
        Ok(())
    }
}
