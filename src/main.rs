#![allow(dead_code)]

use daemonize::Daemonize;
use log::{debug, info};
use nix::sys::socket::{setsockopt, sockopt};
use std::error::Error;
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::os::unix::io::AsRawFd;
use std::panic;
use std::thread;
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

    //create tun
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
        debug!("add address {}", addr4);
        util::add_addr(addr4.into(), tun.name())?;
    };

    if let Some(addr6) = config.loc_tun_in6 {
        debug!("add address {}", addr6);
        util::add_addr(addr6.into(), tun.name())?;
    };

    for (net, _) in &config.routes {
        debug!("add route {}", net);
        util::add_route(net, tun.name(), &config.table, &config.metric)?;
    }

    //create socket
    let server_addr: Option<SocketAddr> = match config.server_addr {
        Some(ref server_addr) => loop {
            let addrs = server_addr.to_socket_addrs().map_err(|_| {
                crate::error::Error::InvalidArg(format!("invalid remote addr {:?}", server_addr))
            });

            match addrs {
                Ok(mut addrs) => break addrs.next(),
                Err(err) => {
                    if config.wait_dns {
                        thread::sleep(config.reconnect_timeout.unwrap());
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
        .unwrap_or(default_listen_addr.parse().unwrap());

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

    //run
    match config.server_addr {
        None => {
            let socket = socket_factory(&config);
            info!(
                "Mini virtual tunneling server on {:}, interface: {:}.",
                socket.local_addr().unwrap(),
                tun.name()
            );

            do_daemonize(&config);

            Server::new(config, socket, tun).run()
        }
        _ => {
            info!(
                "Mini virtual tunneling client to {:}, interface: {:}.",
                server_addr.unwrap(),
                tun.name()
            );

            do_daemonize(&config);

            Client::new(config, &socket_factory, tun).run()
        }
    }
}

fn do_daemonize(config: &Config) {
    if let Some(true) = config.daemonize {
        Daemonize::new().user("nobody").start().unwrap();
    }
}
