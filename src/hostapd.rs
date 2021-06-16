use std::process::{Child, Command};

use std::fs::File;
use std::io::prelude::*;
use std::path::Path;
use std::env;

use std::thread;
use std::time::Duration;

use errors::*;
use config::Config;


pub fn create_phy_if(config: &Config) {
    remove_phy_if(config);
    thread::sleep(Duration::from_millis(250));

    warn!("create phy interface for wifi");
    let _cmd = Command::new("iw").arg("phy").arg("phy0").arg("interface").arg("add").arg(&format!("{}", config.ap_interface)).arg("type").arg("__ap").output();
    thread::sleep(Duration::from_millis(250));
    let _cmd = Command::new("ip").arg("addr").arg("del").arg(&format!("{}/24", config.gateway)).arg("dev").arg(&format!("{}", config.ap_interface)).output();
    let _cmd = Command::new("ip").arg("addr").arg("add").arg(&format!("{}/24", config.gateway)).arg("dev").arg(&format!("{}", config.ap_interface)).output();
}

pub fn remove_phy_if(config: &Config) {
    warn!("remove_phy_if");
    let _cmd = Command::new("iw").arg("dev").arg(&format!("{}", config.ap_interface)).arg("del").output();
}

pub fn start_hostapd(config: &Config) -> Result<Child> {
    // create a config in tmp
    warn!("run hostapd");
    let config_path = write_config(&config.ap_interface, &config.ssid).unwrap();
    Command::new("hostapd")
        .arg(config_path)
        .spawn()
        .chain_err(|| ErrorKind::Hostapd)
}




fn write_config(interface: &str, ssid: &str) -> Result<String> {

    let mut dir = env::temp_dir();
    dir.push("hostapd.config");

    let finished_path = dir.display().to_string();

    let config_params = [
        &format!("interface={}",interface),
        "driver=nl80211",
        &format!("ssid={}",ssid),
        "channel=1",
        "logger_syslog=-1",
        "logger_syslog_level=2",
        "ctrl_interface=/var/run/hostapd",
        "ctrl_interface_group=0",
        "hw_mode=g",
    ];

    let mut file = File::create(dir).expect("failed to open file");

    for row in &config_params{                                                                                                                                                                  
        //file.write_all((*row)).expect("failed to write file");       
        writeln!(file, "{}", row)?;                                                                                                              
    }     
    

    return Ok(finished_path)
}