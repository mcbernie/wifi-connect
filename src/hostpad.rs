use std::process::{Child, Command};

use std::fs::File;
use std::io::prelude::*;
use std::path::Path;
use std::env;

use network_manager::Device;

use errors::*;
use config::Config;


pub fn create_phy_if(config: &Config) {
    remove_phy_if(config)

    cmd := exec.Command("iw", "phy", "phy0", "interface", config.ap_interface, "type", "__ap")
    err := cmd.Run()

    cmd = exec.Command("ip", "addr", "add", &format!("{}/24", config.gateway), "dev", config.ap_interface)
    err = cmd.Run()
}

pub fn remove_phy_if(config: &Config) {
    cmd := exec.Command("iw", config.ap_interface, "ap", "del")
	err := cmd.Run()
}

pub fn start_hostapd(config: &Config) -> Result<Child> {
    // create a config in tmp
    let config_path = write_config(&config.ap_interface, &config.ssid).unwrap();

    Command::new("hostapd")
        .arg(config_path)
        .spawn()
        .chain_err(|| ErrorKind::Hostapd)
}




fn write_config(interface: &str, ssid: &str,) -> Result<&str, Error> {

    let mut dir = env::temp_dir();
    dir.push("hostapd.config");

    let config_params = [
        &format!("interface={}",interface),
        "driver=nl80211"
        &format!("ssid={}",ssid),
        "channel=1"
    ]

    let mut file = File::create(dir).expect("failed to open file");
    defer file.close();
    file.write_all(&config_params).expect("failed to write file");

    return Ok(dir.display())
}