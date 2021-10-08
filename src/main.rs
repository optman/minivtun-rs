#![allow(dead_code)]

use daemonize::Daemonize;
use std::error::Error;
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::panic;
use tun::Device;

mod client;
mod config;
mod cryptor;
mod error;
mod flags;
mod msg;
mod poll;
mod route;
mod server;
mod state;
mod util;
use client::Client;
use config::Config;
use server::Server;

extern crate tun;

fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"),
    );

    let orig_hook = panic::take_hook();
    panic::set_hook(Box::new(move |panic_info| {
        orig_hook(panic_info);
        std::process::exit(1);
    }));

    let mut config = Config::default();
    flags::parse(&mut config)?;

    let server_addr: Option<SocketAddr> = match config.server_addr {
        Some(ref server_addr) => {
            let mut addrs = server_addr.to_socket_addrs().map_err(|_| {
                crate::error::Error::InvalidArg(format!("invalid remote addr {:?}", server_addr))
            })?;

            addrs.next()
        }
        None => None,
    };

    let default_listen_addr4 = SocketAddr::from(([0, 0, 0, 0], 0));
    let default_listen_addr6 = SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], 0));

    let default_listen_addr = match server_addr {
        Some(SocketAddr::V4(_)) => default_listen_addr4,
        Some(SocketAddr::V6(_)) => default_listen_addr6,
        None => default_listen_addr4,
    };

    let listen_addr = config.listen_addr.unwrap_or(default_listen_addr);
    let socket = UdpSocket::bind(listen_addr)?;

    let mut tun_config = tun::configure();
    if let Some(ref name) = config.ifname {
        tun_config.name(name);
    }
    if let Some(mtu) = config.mtu {
        tun_config.mtu(mtu);
    }

    tun_config.up();

    let tun = tun::create(&tun_config)?;
    tun.set_nonblock()?;

    if let Some(addr4) = config.loc_tun_in {
        log::debug!("add address {}", addr4);
        util::add_addr(addr4.into(), tun.name())?;
    };

    if let Some(addr6) = config.loc_tun_in6 {
        log::debug!("add address {}", addr6);
        util::add_addr(addr6.into(), tun.name())?;
    };

    for (net, _) in &config.routes {
        log::debug!("add route {}", net);
        util::add_route(net, tun.name(), &config.table, &config.metric)?;
    }

    match config.server_addr {
        None => {
            log::info!(
                "Mini virtual tunneling server on {:}, interface: {:}.",
                socket.local_addr().unwrap(),
                tun.name()
            );

            if let Some(true) = config.daemonize {
                do_daemonize();
            }

            let svr = Server::new(config, socket, tun);
            svr.run()
        }
        _ => {
            log::info!(
                "Mini virtual tunneling client to {:}, interface: {:}.",
                server_addr.unwrap(),
                tun.name()
            );

            if let Some(true) = config.daemonize {
                do_daemonize();
            }

            let client = Client::new(config, socket, tun);
            client.run()
        }
    }
}

fn do_daemonize() {
    Daemonize::new().user("nobody").start().unwrap();
}
