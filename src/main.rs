#![allow(dead_code)]

use daemonize::Daemonize;
use ipnet::IpNet;
use log::{debug, info};
use std::os::unix::io::AsRawFd;
use std::{panic, process::Command};
use tun::{platform::Device, Device as _};

#[cfg(feature = "holepunch")]
use std::net::UdpSocket;

mod flags;
use minivtun::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"),
    );

    let orig_hook = panic::take_hook();
    panic::set_hook(Box::new(move |panic_info| {
        orig_hook(panic_info);
        std::process::exit(1);
    }));

    let mut config = Config::new();
    flags::parse(&mut config)?;

    //create tun
    let tun = config_tun(&config)?;
    config.with_tun_fd(tun.as_raw_fd());

    let remote_id = {
        #[cfg(not(feature = "holepunch"))]
        {
            config.server_addr.as_ref().cloned()
        }

        #[cfg(feature = "holepunch")]
        config
            .server_addr
            .as_ref()
            .or_else(|| config.rndz.as_ref().and_then(|c| c.remote_id.as_ref()))
            .cloned()
    };

    #[cfg(feature = "holepunch")]
    if let Some(ref mut c) = config.rndz {
        c.with_svr_sk_builder(&create_rndz_svr_sk);
    };

    let socket_factory = config_socket_factory(&mut config);
    config.with_socket_factory(&socket_factory);

    //run
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
            .expect("socket factory not set")(&config)?;
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
    };

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
    };

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
fn create_rndz_svr_sk(config: &Config) -> Result<UdpSocket, Error> {
    let bind_addr = match config.listen_addr {
        Some(addr) => addr,
        None => choose_bind_addr(&config.rndz.as_ref().unwrap().server, config)?,
    };
    let mut s = UdpSocket::bind(bind_addr)?;
    config_socket(&mut s, config)?;
    Ok(s)
}
