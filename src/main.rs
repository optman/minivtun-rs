#![allow(dead_code)]

use daemonize::Daemonize;
use ipnet::IpNet;
use log::{debug, info, warn};
use std::fs;
use std::os::unix::io::AsRawFd;
use std::{panic, process::Command};

use std::io::Read;
#[cfg(feature = "holepunch")]
use std::net::UdpSocket;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use tun::platform::posix::Fd;
use tun::{platform::Device, Device as _};
mod flags;
use minivtun::*;

const CONTROL_PATH_BASE: &str = "/var/run/minivtun/";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize the logger
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"),
    );

    // Set custom panic hook
    let orig_hook = panic::take_hook();
    panic::set_hook(Box::new(move |panic_info| {
        orig_hook(panic_info);
        std::process::exit(1);
    }));

    let mut config = Config::new();
    flags::parse(&mut config)?;

    // Show information only if specified
    if config.info {
        show_info(&config)?;
        return Ok(());
    }

    // Create TUN interface
    let tun = config_tun(&config)?;
    config.with_tun_fd(Fd::new(tun.as_raw_fd()).unwrap());

    // Setup remote ID based on feature flag
    let remote_id = get_remote_id(&config);

    #[cfg(feature = "holepunch")]
    if let Some(ref mut c) = config.rndz {
        c.with_svr_sk_builder(&create_rndz_svr_sk);
    }

    let socket_factory = config_socket_factory(&mut config);
    config.with_socket_factory(&socket_factory);

    // Create Unix control socket
    let control_path = Path::new(CONTROL_PATH_BASE)
        .join(tun.name())
        .with_extension("sock");
    if control_path.exists() {
        fs::remove_file(&control_path)?;
    }

    fs::create_dir_all(CONTROL_PATH_BASE)?;
    let control_socket = UnixListener::bind(control_path)?;
    config.with_control_fd(control_socket);

    // Warn if encryption is not enabled
    if config.cryptor.is_none() {
        warn!("*** WARNING: Transmission will not be encrypted.");
    }

    // Run client or server based on configuration
    if let Some(remote_id) = remote_id {
        info!(
            "Mini virtual tunneling client to {:}, interface: {:}.",
            remote_id,
            tun.name()
        );

        do_daemonize(&config);
        Client::new(config)?.run()
    } else {
        let socket = config
            .socket_factory()
            .as_ref()
            .expect("socket factory not set")(&config, config.wait_dns)?;
        info!(
            "Mini virtual tunneling server on {:}, interface: {:}.",
            socket.local_addr().expect("local address not set"),
            tun.name()
        );

        config.with_socket(socket);

        do_daemonize(&config);
        Server::new(config)?.run()
    }
}

fn show_info(config: &Config) -> Result<(), Box<dyn std::error::Error>> {
    let control_path = Path::new(CONTROL_PATH_BASE)
        .join(
            config
                .ifname
                .as_ref()
                .expect("interface name not set")
                .replace("%d", "0"),
        )
        .with_extension("sock");

    if let Ok(mut ctrl) = UnixStream::connect(control_path) {
        let mut buf = String::new();
        ctrl.read_to_string(&mut buf)?;
        println!("{}", buf);
    }
    Ok(())
}

fn do_daemonize(config: &Config) {
    if config.daemonize {
        Daemonize::new()
            .user("nobody")
            .start()
            .expect("start daemonize fail");
    }
}

fn add_addr(addr: IpNet, dev: &str) -> Result<(), Error> {
    let mut c = Command::new("ip");
    if let IpNet::V6(_) = addr {
        c.arg("-6");
    }

    if !c
        .arg("addr")
        .arg("add")
        .arg(addr.to_string())
        .arg("dev")
        .arg(dev)
        .status()
        .map_or(false, |c| c.success())
    {
        Err(Error::AddAddrFail)?
    }

    Ok(())
}

fn add_route(
    addr: &IpNet,
    dev: &str,
    table: &Option<String>,
    metric: &Option<String>,
) -> Result<(), Error> {
    let mut c = Command::new("ip");
    if let IpNet::V6(_) = addr {
        c.arg("-6");
    }

    c.arg("route")
        .arg("add")
        .arg(addr.to_string())
        .arg("dev")
        .arg(dev);

    if let Some(table) = table {
        c.arg("table");
        c.arg(table);
    }

    if let Some(metric) = metric {
        c.arg("metric");
        c.arg(metric);
    }

    if c.status().map_or(false, |c| c.success()) {
        return Ok(());
    }

    Err(Error::AddRouteFail)?
}

fn config_tun(config: &Config) -> Result<Device, Box<dyn std::error::Error>> {
    let mut tun_config = tun::configure();
    if let Some(ref name) = config.ifname {
        tun_config.name(name);
    }

    tun_config.mtu(config.mtu);

    tun_config.up();

    let tun: Device = tun::create(&tun_config)?;
    tun.set_nonblock()?;

    if let Some(addr4) = config.loc_tun_in {
        debug!("add address {}", addr4);
        add_addr(addr4.into(), tun.name())?;
    };

    if let Some(addr6) = config.loc_tun_in6 {
        debug!("add address {}", addr6);
        add_addr(addr6.into(), tun.name())?;
    };

    for (net, _) in &config.routes {
        debug!("add route {}", net);
        add_route(net, tun.name(), &config.table, &config.metric)?;
    }

    Ok(tun)
}

#[cfg(feature = "holepunch")]
fn create_rndz_svr_sk(config: &Config, wait_dns: bool) -> Result<UdpSocket, Error> {
    let bind_addr = match config.listen_addr {
        Some(addr) => addr,
        None => choose_bind_addr(
            config.rndz.as_ref().unwrap().server.as_deref(),
            config,
            wait_dns,
        )?,
    };
    let mut s = UdpSocket::bind(bind_addr)?;
    config_socket(&mut s, config)?;
    Ok(s)
}

fn get_remote_id(config: &Config) -> Option<String> {
    #[cfg(not(feature = "holepunch"))]
    {
        config.server_addrs.as_ref().map(|v| format!("{:?}", v))
    }

    #[cfg(feature = "holepunch")]
    {
        config
            .server_addrs
            .as_ref()
            .map(|v| format!("{:?}", v))
            .or_else(|| config.rndz.as_ref().and_then(|c| c.remote_id.clone()))
    }
}
