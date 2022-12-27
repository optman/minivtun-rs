#![allow(dead_code)]

use daemonize::Daemonize;
use ipnet::IpNet;
use log::{debug, info};
use nix::sys::socket::{setsockopt, sockopt};
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::os::unix::io::AsRawFd;
use std::{panic, process::Command, thread};
use tun::Device;

mod flags;
use minivtun::{Client, Config, Error, Server};

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
    let mut tun_config = tun::configure();
    if let Some(ref name) = config.ifname {
        tun_config.name(name);
    }

    tun_config.mtu(config.mtu);

    tun_config.up();

    let tun = tun::create(&tun_config)?;
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

    config.with_tun_fd(tun.as_raw_fd());

    //create socket
    let server_addr: Option<SocketAddr> = match config.server_addr {
        Some(ref server_addr) => loop {
            let addrs = server_addr
                .to_socket_addrs()
                .map_err(|_| Error::InvalidArg(format!("invalid remote addr {:?}", server_addr)));

            match addrs {
                Ok(mut addrs) => break addrs.next(),
                Err(err) => {
                    if config.wait_dns {
                        thread::sleep(config.reconnect_timeout);
                        continue;
                    } else {
                        return Err(Box::new(err));
                    }
                }
            }
        },
        None => None,
    };

    let default_listen_addr = match server_addr {
        Some(SocketAddr::V4(_)) => "0.0.0.0:0",
        Some(SocketAddr::V6(_)) => "[::]:0",
        None => "0.0.0.0:0",
    };

    let listen_addr = config
        .listen_addr
        .unwrap_or_else(|| default_listen_addr.parse().unwrap());

    let socket_factory = |config: &Config| {
        let socket = UdpSocket::bind(listen_addr).unwrap();
        socket.set_nonblocking(true).unwrap();

        #[cfg(target_os = "linux")]
        if let Some(fwmark) = config.fwmark {
            debug!("set fwmark {}", fwmark);
            setsockopt(socket.as_raw_fd(), sockopt::Mark, &fwmark).unwrap();
        }

        socket
    };

    config.with_socket_factory(&socket_factory);

    //run
    match config.server_addr {
        None => {
            let socket = socket_factory(&config);
            info!(
                "Mini virtual tunneling server on {:}, interface: {:}.",
                socket.local_addr().unwrap(),
                tun.name()
            );

            config.with_socket(socket);

            do_daemonize(&config);

            Server::new(config).run()
        }
        _ => {
            info!(
                "Mini virtual tunneling client to {:}, interface: {:}.",
                server_addr.unwrap(),
                tun.name()
            );

            do_daemonize(&config);

            Client::new(config).run()
        }
    }
}

fn do_daemonize(config: &Config) {
    if config.daemonize {
        Daemonize::new().user("nobody").start().unwrap();
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
