use daemonize::Daemonize;
use ipnet::IpNet;
use log::{debug, info, warn};
use std::fs;
use std::io::Read;
use std::os::fd::{FromRawFd, IntoRawFd, OwnedFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::{panic, process::Command};
use tun::{AbstractDevice, Device};
mod flags;
use minivtun::*;
use std::rc::Rc;

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

    let config = Rc::new(config);
    let mut builder = RuntimeBuilder::new(config.clone());

    // Create TUN interface
    let tun = config_tun(&config)?;
    let tun_name = tun.tun_name()?;
    builder.with_tun_fd(unsafe { OwnedFd::from_raw_fd(tun.into_raw_fd()) });

    // Create Unix control socket
    let control_path = Path::new(CONTROL_PATH_BASE)
        .join(&tun_name)
        .with_extension("sock");
    if control_path.exists() {
        fs::remove_file(&control_path)?;
    }

    fs::create_dir_all(CONTROL_PATH_BASE)?;
    let control_socket = UnixListener::bind(control_path)?;
    builder.with_control_fd(control_socket);

    // Warn if encryption is not enabled
    if config.cryptor.is_none() {
        warn!("*** WARNING: Transmission will not be encrypted.");
    }

    let rt = builder.build()?;

    // Run client or server based on configuration
    if let Some(remote_id) = get_remote_id(&config) {
        info!(
            "Mini virtual tunneling client to {:}, interface: {:}.",
            remote_id, &tun_name
        );

        do_daemonize(&config);
        Client::new(config, rt)?.run()
    } else {
        info!(
            "Mini virtual tunneling server on {:}, interface: {:}.",
            rt.socket()
                .ok_or(std::io::Error::other("socket not created"))
                .and_then(|s| s.local_addr())
                .map(|v| v.to_string())
                .unwrap_or_else(|_| "<NA>".to_string()),
            &tun_name
        );

        do_daemonize(&config);
        Server::new(config, rt)?.run()
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

    if c.arg("addr")
        .arg("add")
        .arg(addr.to_string())
        .arg("dev")
        .arg(dev)
        .status()
        .map_or(false, |c| c.success())
    {
        return Ok(());
    }

    Err(Error::AddAddrFail)
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

    Err(Error::AddRouteFail)
}

fn config_tun(config: &Config) -> Result<Device, Box<dyn std::error::Error>> {
    let mut tun_config = tun::configure();
    if let Some(ref name) = config.ifname {
        tun_config.tun_name(name);
    }

    tun_config.mtu(config.mtu);

    tun_config.up();

    let tun: Device = tun::create(&tun_config)?;
    let tun_name = tun.tun_name()?;
    tun.set_nonblock()?;

    if let Some(addr4) = config.loc_tun_in {
        debug!("add address {}", addr4);
        add_addr(addr4.into(), &tun_name)?;
    };

    if let Some(addr6) = config.loc_tun_in6 {
        debug!("add address {}", addr6);
        add_addr(addr6.into(), &tun_name)?;
    };

    for (net, _) in &config.routes {
        debug!("add route {}", net);
        add_route(net, &tun_name, &config.table, &config.metric)?;
    }

    Ok(tun)
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
