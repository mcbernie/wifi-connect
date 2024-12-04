use std::thread;
use itertools::Itertools;
use log::{debug, error, info, warn};
use serde_derive::{Deserialize, Serialize};
use std::time::Duration;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::net::Ipv4Addr;
use anyhow::{anyhow, bail, Result};

use network_manager::{AccessPoint, AccessPointCredentials, Connection, ConnectionState,
                      Connectivity, Device, DeviceState, DeviceType, NetworkManager, Security,
                      ServiceState};

//use dnsmasq::start_dnsmasq;
//use hostapd::{start_hostapd, create_phy_if, remove_phy_if};

use crate::config::Config;
use crate::exit::{exit, trap_exit_signals, ExitResult};
use crate::server::start_server;
use std::str::{FromStr,from_utf8};
use std::fs;


pub enum NetworkCommand {
    Activate,
    Timeout,
    Exit,
    EthDhcp,
    Connect {
        ssid: String,
        identity: String,
        passphrase: String,
    },
    EthConnect {
        ip: String,
        sn: String,
        gw: String,
        dns: String,
    },
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct Network {
    ssid: String,
    security: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub enum EthernetTyp {
    None,
    Dhcp(Ipv4Addr,Ipv4Addr,Ipv4Addr,Ipv4Addr),
    Static(Ipv4Addr,Ipv4Addr,Ipv4Addr,Ipv4Addr),
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct NetworkConfiguration {
    ssids: Vec<Network>,
    ethernet: EthernetTyp,
}

pub enum NetworkCommandResponse {
    Network(NetworkConfiguration),
}

struct NetworkCommandHandler {
    manager: NetworkManager,
    device: Device,
    ethernet_device: Option<Device>,
    access_points: Vec<AccessPoint>,
    config: Config,
    server_tx: Sender<NetworkCommandResponse>,
    network_rx: Receiver<NetworkCommand>,
    activated: bool,
}

impl NetworkCommandHandler {
    fn new(config: &Config, exit_tx: &Sender<ExitResult>) -> Result<Self> {
        let (network_tx, network_rx) = channel();

        Self::spawn_trap_exit_signals(exit_tx, network_tx.clone());

        let manager = NetworkManager::new();
        debug!("NetworkManager connection initialized");

        let device = find_device(&manager, &config.interface)?;

        let access_points = get_access_points(&device)?;
        
        let ethernet_device = {
            if let Ok(device) = find_eth_device(&manager, &config.eth_inferface) {
                Some(device)
            } else {
                None
            }
        };


        let (server_tx, server_rx) = channel();

        warn!("spawn server");
        Self::spawn_server(config, exit_tx, server_rx, network_tx.clone());

        warn!("spawn_timeouter");
        Self::spawn_activity_timeout(config, network_tx.clone());

        let config = config.clone();
        let activated = false;

        

        Ok(NetworkCommandHandler {
            manager,
            device,
            ethernet_device,
            access_points,
            config,
            server_tx,
            network_rx,
            activated,
        })
    }

    fn spawn_server(
        config: &Config,
        exit_tx: &Sender<ExitResult>,
        server_rx: Receiver<NetworkCommandResponse>,
        network_tx: Sender<NetworkCommand>,
    ) {
        let gateway = config.gateway;
        let listening_port = config.listening_port;
        let exit_tx_server = exit_tx.clone();

        // determine if in "CONFIGMODE.tmp" exists in TMP
        // disable configmode!

        let ui_directory = config.ui_directory.clone();
        /*let ui_directory = match std::path::Path::new("/var/CONFIGMODE").exists() {
            true => {
                // remove 
                let _  = fs::remove_file("/var/CONFIGMODE");

                config.ui_directory.clone()
            },
            false => {
                config.pre_ui_directory.clone()
            }
        };*/
        

        thread::spawn(move || {
            start_server(
                gateway,
                listening_port,
                server_rx,
                network_tx,
                exit_tx_server,
                &ui_directory,
            );
        });
    }

    fn spawn_activity_timeout(config: &Config, network_tx: Sender<NetworkCommand>) {
        let activity_timeout = config.activity_timeout;

        if activity_timeout == 0 {
            return;
        }

        thread::spawn(move || {
            thread::sleep(Duration::from_secs(activity_timeout));

            if let Err(err) = network_tx.send(NetworkCommand::Timeout) {
                error!(
                    "Sending NetworkCommand::Timeout failed: {:#?}",
                    err
                );
            }
        });
    }

    fn spawn_trap_exit_signals(exit_tx: &Sender<ExitResult>, network_tx: Sender<NetworkCommand>) {
        let exit_tx_trap = exit_tx.clone();

        thread::spawn(move || {
            if let Err(e) = trap_exit_signals() {
                exit(&exit_tx_trap, e);
                return;
            }

            if let Err(err) = network_tx.send(NetworkCommand::Exit) {
                error!("Sending NetworkCommand::Exit failed: {:#?}", err);
            }
        });
    }

    fn run(&mut self, exit_tx: &Sender<ExitResult>) {
        let result = self.run_loop();
        self.stop(exit_tx, result);
    }

    fn run_loop(&mut self) -> ExitResult {
        loop {
            let command = self.receive_network_command()?;

            match command {
                NetworkCommand::Activate => {
                    warn!("activate received");
                    self.activate()?;
                },
                NetworkCommand::Timeout => {
                    warn!("receive timeout");
                    //if !self.activated {
                        info!("Timeout reached. Exiting...");
                        return Ok(());
                    //}
                },
                NetworkCommand::Exit => {
                    warn!("recevie exit");
                    info!("Exiting...");
                    return Ok(());
                },
                NetworkCommand::EthDhcp => {
                    warn!("ethdhcp received");
                    if self.connect_dhcp()? {
                        return Ok(());
                    }
                },
                NetworkCommand::EthConnect {
                    ip,
                    sn,
                    gw,
                    dns,
                } => {
                    warn!("ethconnect received");
                    if self.connect_static(&ip, &sn, &gw, &dns)? {
                        warn!("connected");
                        return Ok(());
                    }
                },
                NetworkCommand::Connect {
                    ssid,
                    identity,
                    passphrase,
                } => {
                    warn!("connect");
                    if self.connect(&ssid, &identity, &passphrase)? {
                        return Ok(());
                    }
                },
            }
        }
    }

    fn receive_network_command(&self) -> Result<NetworkCommand> {
        match self.network_rx.recv() {
            Ok(command) => Ok(command),
            Err(e) => {
                // Sleep for a second, so that other threads may log error info.
                thread::sleep(Duration::from_secs(1));
                Err(e.into())
            },
        }
    }

    fn stop(&mut self, exit_tx: &Sender<ExitResult>, result: ExitResult) {
        use std::process::Command;
        warn!("stop");
        //let _ = self.dnsmasq.kill();
        //let _ = self.hostapd.kill();


        //remove_phy_if(&self.config);

        /*if let Some(ref connection) = self.portal_connection {
            let _ = stop_portal_impl(connection, &self.config);
        }*/

        match std::path::Path::new("/var/PRECONFIGMODE").exists() {
            true => {
                use std::fs::File;
                use std::io::prelude::*;
                let _  = fs::remove_file("/var/PRECONFIGMODE");
                match File::create("/var/CONFIGMODE") {
                    Ok(mut file) => {
                        info!("create configmode file and reboot...");
                        file.write_all(b"ENABLE CONFIG MODE");
                        let _output = Command::new("reboot").arg("now").output();
                    },
                    Err(e) => {
                        debug!("Error on set Config Mode");
                    }
                }
            },
            false => {
                
            }
        };

        

        let _ = exit_tx.send(result);
    }

    fn activate(&mut self) -> ExitResult {
        self.activated = true;

        warn!("activate...(get networks and access points");

        let aps = get_access_points(&self.device).unwrap();
        self.access_points = aps;
        let ssids = get_networks(&self.access_points);
        
        let ethernet = {
            match &self.ethernet_device {
                Some(d) => {
                    let interface = d.interface();
                    match get_eth_uuid(&interface.to_string()) {
                        Ok(uuid) => {
                            info!("uuid for {} is {}", interface, uuid);
                            if uuid != "" {
                                match is_eth_dhcp(&uuid) {
                                    Ok(is_dhcp) => {
                                        
                                        let default_address = Ipv4Addr::from_str("0.0.0.0").unwrap();

                                        let ip4_address = {
                                            let ip = match get_eth_ip(&uuid) {
                                                Ok(ip) => ip,
                                                Err(_e) => "".to_string(),
                                            };
                                            info!("ip for {} is {}", interface, ip);
                                            match Ipv4Addr::from_str(&ip) {
                                                Ok(ip) => ip,
                                                Err(_e) => {
                                                    default_address
                                                }
                                            }
                                        };

                                        let gw_address = {
                                            let ip = match get_eth_gw(&uuid) {
                                                Ok(ip) => ip,
                                                Err(_e) => "".to_string(),
                                            };
                                            info!("gw for {} is {}", interface, ip);
                                            match Ipv4Addr::from_str(&ip) {
                                                Ok(ip) => ip,
                                                Err(_e) => {
                                                    default_address
                                                }
                                            }
                                        };

                                        let dns_address = {
                                            let ip = match get_eth_dns(&uuid) {
                                                Ok(ip) => ip,
                                                Err(_e) => "".to_string(),
                                            };
                                            info!("dns for {} is {}", interface, ip);
                                            match Ipv4Addr::from_str(&ip) {
                                                Ok(ip) => ip,
                                                Err(_e) => {
                                                    default_address
                                                }
                                            }
                                        };



                                        let subnet = Ipv4Addr::from_str("255.255.255.0").unwrap();



                                        if is_dhcp == true {
                                            info!("DHCP is enabled");
                                            EthernetTyp::Dhcp(
                                                ip4_address, subnet, gw_address, dns_address
                                            )
                                        } else {
                                            info!("DHCP is disabled");
                                            EthernetTyp::Static(
                                                ip4_address, subnet, gw_address, dns_address
                                            )
                                        }
                                    },
                                    Err(_e) => {
                                        EthernetTyp::None
                                    }
                                }
                            } else {
                                EthernetTyp::None
                            }
                        },
                        Err(_e) => {
                            EthernetTyp::None
                        }
                    }
                },
                None => {
                    EthernetTyp::None
                }
            }
        };

        let nc = NetworkConfiguration{
            ssids: ssids,
            ethernet: ethernet,
        };

        
        warn!("send command after scan for networks");

        // determine if ethernet is aviable
        self.server_tx
            .send(NetworkCommandResponse::Network(nc))?;

        Ok(())
            //.chain_err(|| ErrorKind::SendAccessPointSSIDs)
    }

    fn connect_dhcp(&mut self) -> Result<bool> {
        use std::process::Command;

        match &self.ethernet_device {
            Some(device) => {
                let interface = device.interface().to_string();
                match get_eth_uuid(&interface) {
                    Ok(uuid) => {
                        if uuid != "" {
                            info!("remove existing connection {}", uuid);
                            let _result = Command::new("nmcli")
                                .arg("c")
                                .arg("del")
                                .arg(uuid)
                                .output()
                                .expect("failed to remove existing connect");
                        }


                    },
                    Err(_) => {},
                };

                let _output = Command::new("nmcli")
                    .arg("c")
                    .arg("add") 
                    .arg("con-name") 
                    .arg(format!("\"dhcp-{}\"", &interface))
                    .arg("ifname")
                    .arg(&interface)
                    .arg("type")
                    .arg("ethernet")
                    .output()
                    .expect("failed to crate new connection");
                
                let _output = Command::new("nmcli")
                    .arg("c")
                    .arg("mod") 
                    .arg(format!("\"dhcp-{}\"", &interface))
                    .arg("ipv4.method")
                    .arg("auto")
                    .output()
                    .expect(&format!("failed to set dns for dhcp-{}", &interface));
                    
                let _output = Command::new("nmcli")
                    .arg("c")
                    .arg("up") 
                    .arg(format!("\"dhcp-{}\"", &interface))
                    .arg("iface")
                    .arg(&interface)
                    .output()
                    .expect(&format!("failed to go online with dhcp-{}", &interface));
                

                match wait_for_connectivity(&self.manager, 20) {
                    Ok(has_connectivity) => {
                        if has_connectivity {
                            info!("Internet connectivity established");
                        } else {
                            warn!("Cannot establish Internet connectivity");
                        }
                    },
                    Err(err) => error!("Getting Internet connectivity failed: {}", err),
                }

                return Ok(true);
            },
            None => {
                error!("Could not find ethernet device")
            }
        }
        
        
        Ok(false)
    }

    fn connect_static(&mut self, ip: &str, sn: &str, gw: &str, dns: &str) -> Result<bool> {
        use std::process::Command;
        info!("connect_static: {} {} {} {}", ip, sn, gw, dns);
        match &self.ethernet_device {
            Some(device) => {
                let interface = device.interface().to_string();
                match get_eth_uuid(&interface) {
                    Ok(uuid) => {
                        if uuid != "" {
                            info!("remove existing connection {}", uuid);
                            let _result = Command::new("nmcli")
                                .arg("c")
                                .arg("del")
                                .arg(uuid)
                                .output()
                                .expect("failed to remove existing connect");
                        }


                    },
                    Err(_) => {},
                };

                let output = Command::new("nmcli")
                    .arg("c")
                    .arg("add") 
                    .arg("con-name") 
                    .arg(format!("\"static-{}\"", &interface))
                    .arg("ifname")
                    .arg(&interface)
                    .arg("type")
                    .arg("ethernet")
                    .arg("ip4")
                    .arg(format!("{}/24", ip))
                    .arg("gw4")
                    .arg(gw)
                    .output()
                    .expect("failed to crate new connection");
                info!("err add:{}", from_utf8(&output.stderr).unwrap());
                info!("add:{}", from_utf8(&output.stdout).unwrap());
                

                let output = Command::new("nmcli")
                    .arg("c")
                    .arg("mod") 
                    .arg(format!("\"static-{}\"", &interface))
                    .arg("ipv4.dns")
                    .arg(dns)
                    .output()
                    .expect(&format!("failed to set dns for static-{}", &interface));
                info!("err mod:{}", from_utf8(&output.stderr).unwrap());
                info!("mod:{}", from_utf8(&output.stdout).unwrap());
                    
                let output = Command::new("nmcli")
                    .arg("c")
                    .arg("up") 
                    .arg(format!("\"static-{}\"", &interface))
                    .output()
                    .expect(&format!("failed to go online with static-{}", &interface));
                info!("err up:{}", from_utf8(&output.stderr).unwrap());
                info!("up:{}", from_utf8(&output.stdout).unwrap());
                

                match wait_for_connectivity(&self.manager, 20) {
                    Ok(has_connectivity) => {
                        if has_connectivity {
                            info!("Internet connectivity established");
                        } else {
                            warn!("Cannot establish Internet connectivity");
                        }
                    },
                    Err(err) => error!("Getting Internet connectivity failed: {}", err),
                }

                return Ok(true);
            },
            None => {
                error!("Could not find ethernet device")
            }
        }
        
        
        Ok(false)
    }

    fn connect(&mut self, ssid: &str, identity: &str, passphrase: &str) -> Result<bool> {
        delete_existing_connections_to_same_network(&self.manager, ssid);

        self.access_points = get_access_points(&self.device)?;

        if let Some(access_point) = find_access_point(&self.access_points, ssid) {
            let wifi_device = self.device.as_wifi_device().unwrap();

            info!("Connecting to access point '{}'...", ssid);

            let credentials = init_access_point_credentials(access_point, identity, passphrase);

            match wifi_device.connect(access_point, &credentials) {
                Ok((connection, state)) => {
                    if state == ConnectionState::Activated {
                        match wait_for_connectivity(&self.manager, 20) {
                            Ok(has_connectivity) => {
                                if has_connectivity {
                                    info!("Internet connectivity established");
                                } else {
                                    warn!("Cannot establish Internet connectivity");
                                }
                            },
                            Err(err) => error!("Getting Internet connectivity failed: {}", err),
                        }

                        return Ok(true);
                    }

                    if let Err(err) = connection.delete() {
                        error!("Deleting connection object failed: {}", err)
                    }

                    warn!(
                        "Connection to access point not activated '{}': {:?}",
                        ssid, state
                    );
                },
                Err(e) => {
                    warn!("Error connecting to access point '{}': {}", ssid, e);
                },
            }
        }

        self.access_points = get_access_points(&self.device)?;

        Ok(false)
    }
}

fn init_access_point_credentials(
    access_point: &AccessPoint,
    identity: &str,
    passphrase: &str,
) -> AccessPointCredentials {
    if access_point.security.contains(Security::ENTERPRISE) {
        warn!("Enterprise security detected identity: {}, passphrase: {}", identity, passphrase);
        AccessPointCredentials::Enterprise {
            identity: identity.to_string(),
            passphrase: passphrase.to_string(),
        }
    } else if access_point.security.contains(Security::WPA2)
        || access_point.security.contains(Security::WPA)
    {
        warn!("WPA / WPA2 security detected passphrase: {}", passphrase);
        AccessPointCredentials::Wpa {
            passphrase: passphrase.to_string(),
        }
    } else if access_point.security.contains(Security::WEP) {
        AccessPointCredentials::Wep {
            passphrase: passphrase.to_string(),
        }
    } else {
        AccessPointCredentials::None
    }
}

pub fn process_network_commands(config: &Config, exit_tx: &Sender<ExitResult>) {
    let mut command_handler = match NetworkCommandHandler::new(config, exit_tx) {
        Ok(command_handler) => command_handler,
        Err(e) => {
            exit(exit_tx, e);
            return;
        },
    };

    command_handler.run(exit_tx);
}

pub fn init_networking(config: &Config) -> Result<()> {
    start_network_manager_service()?;

    delete_exising_wifi_connect_ap_profile(&config.ssid)?;//.chain_err(|| ErrorKind::DeleteAccessPoint)
    Ok(())
}

fn get_eth_uuid(interface: &String) -> Result<String> {
    info!("get eth uuid for {}", interface);
    use std::process::Command;
    let output = Command::new("nmcli")
        .arg("-g")
        .arg("general.con-uuid")
        .arg("device") 
        .arg("show")
        .arg(interface)
        .output()
        .expect("failed to execute get con-uuid");

    
    Ok(from_utf8(&output.stdout).unwrap().to_string().trim().to_string())
}

fn is_eth_dhcp(con_uuid: &String) -> Result<bool> {

    info!("get eth dhcp settings for {}", con_uuid);
    use std::process::Command;
    let output = Command::new("nmcli")
        .arg("-g")
        .arg("ipv4.method")
        .arg("c") 
        .arg("s")
        .arg(con_uuid)
        .output()
        .expect("failed to execute get ipv4.method");

    let outputstr = from_utf8(&output.stdout).unwrap().trim();
    info!("ipv4.method for {} is {}", con_uuid, outputstr);
    match outputstr {
        "auto" => {
            Ok(true)
        }, 
        _ => {
            Ok(false)
        }
    }
}

fn get_eth_ip(con_uuid: &String) -> Result<String> {
    info!("get eth IP for {}", con_uuid);

    use std::process::Command;
    let output = Command::new("nmcli")
        .arg("-g")
        .arg("IP4.ADDRESS")
        .arg("c") 
        .arg("s")
        .arg(con_uuid)
        .output()
        .expect("failed to execute get IP4.ADDRESS");

    let o = from_utf8(&output.stdout).unwrap().to_string();
    
    let trimmed_o = o.trim().split("/").collect::<Vec<&str>>();

    Ok(trimmed_o[0].to_string())
}

fn get_eth_gw(con_uuid: &String) -> Result<String> {
    info!("get eth GW for {}", con_uuid);

    use std::process::Command;
    let output = Command::new("nmcli")
        .arg("-g")
        .arg("IP4.GATEWAY")
        .arg("c") 
        .arg("s")
        .arg(con_uuid)
        .output()
        .expect("failed to execute get IP4.GATEWAY");

    Ok(from_utf8(&output.stdout).unwrap().to_string().trim().to_string())
}

fn get_eth_dns(con_uuid: &String) -> Result<String> {
    info!("get eth DNS for {}", con_uuid);

    use std::process::Command;
    let output = Command::new("nmcli")
        .arg("-g")
        .arg("IP4.DNS")
        .arg("c") 
        .arg("s")
        .arg(con_uuid)
        .output()
        .expect("failed to execute get IP4.DNS");

    Ok(from_utf8(&output.stdout).unwrap().to_string().trim().to_string())
}

pub fn find_eth_device(manager: &NetworkManager, interface: &Option<String>) -> Result<Device> {
    if let Some(ref interface) = *interface {
        let device = manager
            .get_device_by_interface(interface).map_err(|e| anyhow!("Error: {:?} - DeviceByInterface {:?}", e, interface.clone()))?;

        info!("Targeted Ethernet device: {}", interface);

        if *device.device_type() != DeviceType::Ethernet {
            bail!(" NotAWiFiDevice({:?})", interface.clone())
        }

        if device.get_state().map_err(|e| anyhow!("kann state nicht abrufen {:?}", e))? == DeviceState::Unavailable {
            bail!(" Unaviable({:?})", interface.clone())
        }

        Ok(device)
    } else {
        let devices = manager.get_devices().map_err(|e| anyhow!("kann devices nicht abrufen {:?}", e))?;

        if let Some(device) = find_ethernet_device(devices)? {
            info!("Ethernet device: {}", device.interface());
            Ok(device)
        } else {
            bail!("no Ethernet device found!")
        }
    }
} 

pub fn find_device(manager: &NetworkManager, interface: &Option<String>) -> Result<Device> {
    if let Some(ref interface) = *interface {
        let device = manager
            .get_device_by_interface(interface).map_err(|e| anyhow!("Error: {:?} - DeviceByInterface {:?}", e, interface.clone()))?;

        info!("Targeted WiFi device: {}", interface);

        if *device.device_type() != DeviceType::WiFi {
            bail!(" NotAWiFiDevice({:?})", interface.clone())
        }

        if device.get_state().map_err(|e| anyhow!("kann state nicht abrufen {:?}", e))? == DeviceState::Unmanaged {
            bail!(" UnmanagedDevice({:?})", interface.clone())
        }

        Ok(device)
    } else {
        let devices = manager.get_devices().map_err(|e| anyhow!("kann devices nicht abrufen {:?}", e))?;

        if let Some(device) = find_wifi_managed_device(devices)? {
            info!("WiFi device: {}", device.interface());
            Ok(device)
        } else {
            bail!("no Wifi device found!")
        }
    }
}

fn find_wifi_managed_device(devices: Vec<Device>) -> Result<Option<Device>> {
    for device in devices {
        if *device.device_type() == DeviceType::WiFi
            && device.get_state().map_err(|e| anyhow!("kann device state nicht abrufen {:?}", e))? != DeviceState::Unmanaged
        {
            return Ok(Some(device));
        }
    }

    Ok(None)
}

fn find_ethernet_device(devices: Vec<Device>) -> Result<Option<Device>> {
    for device in devices {
        if *device.device_type() == DeviceType::Ethernet
            && device.get_state().map_err(|e| anyhow!("kann device state nicht abrufen {:?}", e))? != DeviceState::Unavailable
        {
            return Ok(Some(device));
        }
    }

    Ok(None)
}

fn get_access_points(device: &Device) -> Result<Vec<AccessPoint>> {
    get_access_points_impl(device).map_err(|e| anyhow!("NoAccessPoints ({:?})",e))
}

fn get_access_points_impl(device: &Device) -> Result<Vec<AccessPoint>> {
    let retries_allowed = 10;
    let mut retries = 0;

    // After stopping the hotspot we may have to wait a bit for the list
    // of access points to become available
    while retries < retries_allowed {
        let wifi_device = device.as_wifi_device().unwrap();
        let mut access_points = wifi_device.get_access_points().map_err(|e| anyhow!("get access points failed: ({:?})", e))?;

        wifi_device.request_scan().map_err(|e| anyhow!("request scan failed {:?}", e))?;
        access_points.retain(|ap| ap.ssid().as_str().is_ok() && ap.ssid().as_str().unwrap() != "");

        if !access_points.is_empty() {
            let remove_duplicates: Vec<_> = access_points.into_iter().unique_by(|ap| ap.ssid.to_owned()).collect();
            info!(
                "Access points: {:?}",
                get_access_points_ssids(&remove_duplicates)
            );
            return Ok(remove_duplicates);
        }

        retries += 1;
        debug!("No access points found - retry #{}", retries);
        thread::sleep(Duration::from_secs(1));
    }

    warn!("No access points found - giving up...");
    Ok(vec![])
}

fn get_access_points_ssids(access_points: &[AccessPoint]) -> Vec<&str> {
    access_points
        .iter()
        .map(|ap| ap.ssid().as_str().unwrap())
        .collect()
}

fn get_networks(access_points: &[AccessPoint]) -> Vec<Network> {
    access_points
        .iter()
        .map(|ap| get_network_info(ap))
        .collect()
}

fn get_network_info(access_point: &AccessPoint) -> Network {
    Network {
        ssid: access_point.ssid().as_str().unwrap().to_string(),
        security: get_network_security(access_point).to_string(),
    }
}

fn get_network_security(access_point: &AccessPoint) -> &str {
    if access_point.security.contains(Security::ENTERPRISE) {
        "enterprise"
    } else if access_point.security.contains(Security::WPA2)
        || access_point.security.contains(Security::WPA)
    {
        "wpa"
    } else if access_point.security.contains(Security::WEP) {
        "wep"
    } else {
        "none"
    }
}

fn find_access_point<'a>(access_points: &'a [AccessPoint], ssid: &str) -> Option<&'a AccessPoint> {
    for access_point in access_points.iter() {
        if let Ok(access_point_ssid) = access_point.ssid().as_str() {
            if access_point_ssid == ssid {
                return Some(access_point);
            }
        }
    }

    None
}

fn wait_for_connectivity(manager: &NetworkManager, timeout: u64) -> Result<bool> {
    let mut total_time = 0;

    loop {
        let connectivity = manager.get_connectivity().map_err(|e| anyhow!("no connectivity {:?}", e))?;

        if connectivity == Connectivity::Full || connectivity == Connectivity::Limited {
            debug!(
                "Connectivity established: {:?} / {}s elapsed",
                connectivity, total_time
            );

            return Ok(true);
        } else if total_time >= timeout {
            debug!(
                "Timeout reached in waiting for connectivity: {:?} / {}s elapsed",
                connectivity, total_time
            );

            return Ok(false);
        }

        ::std::thread::sleep(::std::time::Duration::from_secs(1));

        total_time += 1;

        debug!(
            "Still waiting for connectivity: {:?} / {}s elapsed",
            connectivity, total_time
        );
    }
}

pub fn start_network_manager_service() -> Result<()> {
    let state = match NetworkManager::get_service_state() {
        Ok(state) => state,
        _ => {
            info!("Cannot get the NetworkManager service state");
            return Ok(());
        },
    };

    if state != ServiceState::Active {
        let state = NetworkManager::start_service(15).map_err(|e| anyhow!("error starting NetworkManager ({:?})", e))?;
        if state != ServiceState::Active {
            bail!("NetworkManager State is not Active!");
        } else {
            info!("NetworkManager service started successfully");
        }
    } else {
        debug!("NetworkManager service already running");
    }

    Ok(())
}

fn delete_exising_wifi_connect_ap_profile(ssid: &str) -> Result<()> {
    let manager = NetworkManager::new();

    for connection in &manager.get_connections().map_err(|e| anyhow!("error get connections: ({:?})", e))? {
        if is_access_point_connection(connection) && is_same_ssid(connection, ssid) {
            info!(
                "Deleting already created by WiFi Connect access point connection profile: {:?}",
                connection.settings().ssid,
            );
            connection.delete().map_err(|e| anyhow!("connection delete error: {:?}",e))?;
        }
    }

    Ok(())
}

fn delete_existing_connections_to_same_network(manager: &NetworkManager, ssid: &str) {
    let connections = match manager.get_connections() {
        Ok(connections) => connections,
        Err(e) => {
            error!("Getting existing connections failed: {}", e);
            return;
        },
    };

    for connection in &connections {
        if is_wifi_connection(connection) && is_same_ssid(connection, ssid) {
            info!(
                "Deleting existing WiFi connection to the same network: {:?}",
                connection.settings().ssid,
            );

            if let Err(e) = connection.delete() {
                error!("Deleting existing WiFi connection failed: {}", e);
            }
        }
    }
}

fn is_same_ssid(connection: &Connection, ssid: &str) -> bool {
    connection_ssid_as_str(connection) == Some(ssid)
}

fn connection_ssid_as_str(connection: &Connection) -> Option<&str> {
    // An access point SSID could be random bytes and not a UTF-8 encoded string
    connection.settings().ssid.as_str().ok()
}

fn is_access_point_connection(connection: &Connection) -> bool {
    is_wifi_connection(connection) && connection.settings().mode == "ap"
}

fn is_wifi_connection(connection: &Connection) -> bool {
    connection.settings().kind == "802-11-wireless"
}
