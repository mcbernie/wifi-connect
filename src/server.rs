use anyhow::{anyhow, Error};
use serde_derive::Serialize;
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, Sender};
use std::fmt;
use std::net::Ipv4Addr;
use std::error::Error as StdError;

use serde_json;
use iron::prelude::*;
use iron::{headers, status, typemap, AfterMiddleware, Iron, IronError, IronResult, Request,
           Response, Url};
use iron::modifiers::Redirect;
use iron_cors::CorsMiddleware;
use router::Router;
use staticfile::Static;
use mount::Mount;
use persistent::Write;
use params::{FromValue, Params};

use log::{debug, error, info, warn};
use crate::network::{ConnectionStateResponse, NetworkCommand, NetworkCommandResponse, NetworkConfiguration};
use crate::exit::{exit, ExitResult};

struct RequestSharedState {
    gateway: Ipv4Addr,
    server_rx: Receiver<NetworkCommandResponse>,
    network_tx: Sender<NetworkCommand>,
    exit_tx: Sender<ExitResult>,
    state_rx: Receiver<ConnectionStateResponse>,
}

impl typemap::Key for RequestSharedState {
    type Value = RequestSharedState;
}

#[derive(Debug)]
struct StringError(String);

impl fmt::Display for StringError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

impl StdError for StringError {
    fn description(&self) -> &str {
        &*self.0
    }
}

macro_rules! get_request_ref {
    ($req:ident, $ty:ty, $err:expr) => (
        match $req.get_ref::<$ty>() {
            Ok(val) => val,
            Err(err) => {
                error!($err);
                return Err(IronError::new(err, status::InternalServerError));
            }
        }
    )
}

macro_rules! get_param {
    ($params:ident, $param:expr, $ty:ty) => (
        match $params.get($param) {
            Some(value) => {
                match <$ty as FromValue>::from_value(value) {
                    Some(converted) => converted,
                    None => {
                        let err = format!("Unexpected type for '{}'", $param);
                        error!("{}", err);
                        return Err(IronError::new(StringError(err), status::InternalServerError));
                    }
                }
            },
            None => {
                let err = format!("'{}' not found in request params: {:?}", $param, $params);
                error!("{}", err);
                return Err(IronError::new(StringError(err), status::InternalServerError));
            }
        }
    )
}

macro_rules! get_request_state {
    ($req:ident) => (
        get_request_ref!(
            $req,
            Write<RequestSharedState>,
            "Getting reference to request shared state failed"
        ).as_ref().lock().unwrap()
    )
}

fn exit_with_error(state: &RequestSharedState, e: Error) -> IronResult<Response>
{
    exit(&state.exit_tx, e);
    Err(IronError::new(
        StringError("ein fehler".to_string()),
        status::InternalServerError,
    ))
}

struct RedirectMiddleware;

impl AfterMiddleware for RedirectMiddleware {
    fn catch(&self, req: &mut Request, err: IronError) -> IronResult<Response> {
        
        let gateway = {
            let request_state = get_request_state!(req);
            format!("{}", request_state.gateway)
        };

        

        if let Some(host) = req.headers.get::<headers::Host>() {
            warn!("Redirecting to gateway: {} when !hostname {}", gateway, host.hostname);
            if host.hostname != gateway {
                let url = Url::parse(&format!("http://{}/", gateway)).unwrap();
                return Ok(Response::with((status::Found, Redirect(url))));
            }
        }

        Err(err)
    }
}

pub fn start_server(
    gateway: Ipv4Addr,
    listening_port: u16,
    server_rx: Receiver<NetworkCommandResponse>,
    state_rx: Receiver<ConnectionStateResponse>,
    network_tx: Sender<NetworkCommand>,
    exit_tx: Sender<ExitResult>,
    ui_directory: &PathBuf,
) {
    let exit_tx_clone = exit_tx.clone();
    let gateway_clone = gateway;
    let request_state = RequestSharedState {
        gateway,
        server_rx,
        network_tx,
        exit_tx,
        state_rx,
    };

    let mut router = Router::new();
    router.get("/", Static::new(ui_directory), "index");
    router.get("/networks", networks, "networks");
    router.post("/connect", connect, "connect");
    router.get("/connect_state", connect_status, "connect_state");
    router.post("/start", start, "start");

    let mut assets = Mount::new();
    assets.mount("/", router);
    assets.mount("/css", Static::new(&ui_directory.join("css")));
    assets.mount("/img", Static::new(&ui_directory.join("img")));
    assets.mount("/js", Static::new(&ui_directory.join("js")));

    let cors_middleware = CorsMiddleware::with_allow_any();

    let mut chain = Chain::new(assets);
    chain.link(Write::<RequestSharedState>::both(request_state));
    chain.link_after(RedirectMiddleware);
    chain.link_around(cors_middleware);

    let address = format!("{}:{}", gateway_clone, listening_port);

    info!("Starting HTTP server on {}", &address);

    if let Err(e) = Iron::new(chain).http(&address) {
        exit(
            &exit_tx_clone,
            anyhow!("Error start HTTP SERVER! {:?}",e),
        );
    }
}

fn networks(req: &mut Request) -> IronResult<Response> {
    info!("User connected to the captive portal");

    let request_state = get_request_state!(req);

    

    if let Err(e) = request_state.network_tx.send(NetworkCommand::Activate) {
        return exit_with_error(&request_state, anyhow!("Error SendNetworkCommandActivate {:?}", e));
    }

    let network = match request_state.server_rx.recv() {
        Ok(result) => match result {
            NetworkCommandResponse::Network(network) => network,
        },
        Err(e) => return exit_with_error(&request_state, anyhow!("Error: RecvAccessPointSSIDs {:?}", e)),
    };

    let network_json = match serde_json::to_string(&network) {
        Ok(json) => json,
        Err(e) => return exit_with_error(&request_state, anyhow!("Error: SerializeAccessPointSSIDs {:?}", e)),
    };

    Ok(Response::with((status::Ok, network_json)))
}

fn start(req: &mut Request) -> IronResult<Response> {
    use std::fs::File;
    use std::io::prelude::*;
    use std::process::Command;

    // create tmp file,
    // reboot
    //let request_state = get_request_state!(req);
    info!("start config mode called..");
    

    match File::create("/var/PRECONFIGMODE") {
        Ok(mut file) => {
            info!("create configmode file and reboot...");
            let _ = file.write_all(b"ENABLE CONFIG MODE");
            //let _output = Command::new("reboot").arg("now").output();
            Ok(Response::with(status::Ok))
        },
        Err(e) => {
            debug!("Error on set Config Mode");
            Ok(Response::with(status::Ok))
            //exit_with_error(&request_state, e, ErrorKind::SendNetworkCommandConnect)
        }
    }
    
}

#[derive(Serialize)]
struct ConnectionResponseState {
    status: String,
    connected: bool,
    error:bool,
}

fn connect(req: &mut Request) -> IronResult<Response> {
    
    let params = get_request_ref!(req, Params, "Getting request params failed");
    let network_selection = &*get_param!(params, "network-select", String);
    
    let r = match network_selection {
        "ethernet" => {
            let ip = get_param!(params, "eth_ipaddress", String);
            let sn = get_param!(params, "eth_subnet", String);
            let gw = get_param!(params, "eth_gateway", String);
            let dns = get_param!(params, "eth_dns", String);

            info!("Incoming `connect` to static ip `{}` request", ip);

            let command = NetworkCommand::EthConnect {
                ip,
                sn,
                gw,
                dns,
            };

            let request_state = get_request_state!(req);
            if let Err(e) = request_state.network_tx.send(command) {
                exit_with_error(&request_state, anyhow!("error SendNetworkCommandConnect {:?}", e))
            } else {
                Ok(Response::with(status::Ok))
            }
        },
        "ethernet-dhcp" => {
            let command = NetworkCommand::EthDhcp;

            info!("Incoming `connect` to DHCP request");

            let request_state = get_request_state!(req);
            if let Err(e) = request_state.network_tx.send(command) {
                exit_with_error(&request_state, anyhow!("error SendNetworkCommandConnect {:?}", e))
            } else {
                Ok(Response::with(status::Ok))
            }

        },
        "wlan" => {
            let ssid = get_param!(params, "ssid", String);
            let identity = get_param!(params, "identity", String);
            let passphrase = get_param!(params, "passphrase", String);

            info!("Incoming `connect` to access point `{}` request", ssid);

            let command = NetworkCommand::Connect {
                ssid,
                identity,
                passphrase,
            };

            let request_state = get_request_state!(req);
            if let Err(e) = request_state.network_tx.send(command) {
                exit_with_error(&request_state, anyhow!("error SendNetworkCommandConnect {:?}", e))
            } else {
                Ok(Response::with(status::Ok))
            }
        },
        _ => {
            //exit_with_error(&request_state, e, ErrorKind::SendNetworkCommandConnect)
            Ok(Response::with(status::Ok))
        }
    };

    r
}

fn connect_status(req: &mut Request) -> IronResult<Response> {
    
    let request_state = get_request_state!(req);

    let status = match request_state.state_rx.try_recv() {
        Ok(result) => match result {
            ConnectionStateResponse::Connected => ConnectionResponseState {
                status: "connected".to_string(),
                connected: true,
                error: false,
            },
            ConnectionStateResponse::NoInternet => ConnectionResponseState {
                status: "no_internet".to_string(),
                connected: true,
                error: true,
            },
            ConnectionStateResponse::WrongPassword => ConnectionResponseState {
                status: "wrong_password".to_string(),
                connected: false,
                error: true,
            },
            ConnectionStateResponse::Unkown(u) => ConnectionResponseState {
                status: u,
                connected: false,
                error: true,
            },
            ConnectionStateResponse::UnkownID => ConnectionResponseState {
                status: "unkown_ssid".to_string(),
                connected: false,
                error: true,
            },
            _ => {
                ConnectionResponseState {
                    status: "unkown".to_string(),
                    connected: false,
                    error: false,
                }
            }
        },
        Err(_e) => {
            ConnectionResponseState {
                status: "...".to_string(),
                connected: false,
                error: false,
            }
        },
    };

    let status_json = match serde_json::to_string(&status) {
        Ok(json) => json,
        Err(e) => return exit_with_error(&request_state, anyhow!("Error: SERIALIE CONNECTION STATE {:?}", e)),
    };

    return Ok(Response::with((status::Ok, status_json)))
    
}
