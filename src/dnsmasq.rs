use std::process::{Child, Command};

use network_manager::Device;

use errors::*;
use config::Config;

pub fn start_dnsmasq(config: &Config) -> Result<Child> {
    let args = [
        &format!("--address=/#/{}", config.gateway),
        &format!("--dhcp-range={}", config.dhcp_range),
        &format!("--dhcp-option=option:router,{}", config.gateway),
        &format!("--dhcp-option=114,http://{}", config.gateway),
        &format!("--dhcp-option=103,http://{}", config.gateway),
        &format!("--dhcp-option=37,http://{}", config.gateway),
        &format!("--interface={}", config.ap_interface),
        "--keep-in-foreground",
        "--bind-interfaces",
        "--except-interface=lo",
        "--conf-file",
        "--no-hosts",
    ];

    Command::new("dnsmasq")
        .args(&args)
        .spawn()
        .chain_err(|| ErrorKind::Dnsmasq)
}
