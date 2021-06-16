use std::process::{Child, Command};

use std::fs::File;
use std::io::prelude::*;
use std::path::Path;
use std::env;

use errors::*;
use config::Config;


pub fn create_phy_if(config: &Config) {
    remove_phy_if(config);

    let _cmd = Command::new("iw").arg("phy").arg("phy0").arg("interface").arg(config.ap_interface).arg("type").arg("__ap").output();
    let _cmd = Command::new("ip").arg("addr").arg("add").arg(&format!("{}/24", config.gateway)).arg("dev").arg(config.ap_interface).output();
}

pub fn remove_phy_if(config: &Config) {
    let _cmd = Command::new("iw").arg(config.ap_interface).arg("ap").arg("del").output();
}

pub fn start_hostapd(config: &Config) -> Result<Child> {
    // create a config in tmp
    let config_path = write_config(&config.ap_interface, &config.ssid).unwrap();

    Command::new("hostapd")
        .arg(config_path)
        .spawn()
        .chain_err(|| ErrorKind::Hostapd)
}




fn write_config(interface: &str, ssid: &str) -> Result<String> {

    let mut dir = env::temp_dir();
    dir.push("hostapd.config");

    let config_params = [
        &format!("interface={}",interface),
        "driver=nl80211",
        &format!("ssid={}",ssid),
        "channel=1",
    ];

    let mut file = File::create(dir).expect("failed to open file");
    file.write_all(&config_params).expect("failed to write file");

    return Ok(dir.display())
}