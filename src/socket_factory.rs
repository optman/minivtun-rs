use crate::*;
#[cfg(target_os = "linux")]
use log::debug;
#[cfg(feature = "holepunch")]
use log::error;
#[cfg(target_os = "linux")]
use nix::sys::socket::{setsockopt, sockopt};
#[cfg(target_os = "linux")]
use std::os::unix::io::AsRawFd;

use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::thread;
use util::build_server_addr;

pub fn choose_bind_addr(
    server_addr: Option<&str>,
    config: &Config,
    wait_dns: bool,
) -> Result<SocketAddr, Error> {
    let server_addr: Option<SocketAddr> = match server_addr {
        Some(ref server_addr) => loop {
            let addrs = server_addr.to_socket_addrs().map_err(|_| {
                Error::InvalidArg(format!("invalid remote addr or dns fail {:?}", server_addr))
            });

            match addrs {
                Ok(mut addrs) => break addrs.next(),
                Err(err) => {
                    if wait_dns {
                        thread::sleep(config.reconnect_timeout);
                        continue;
                    } else {
                        return Err(err);
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

    Ok(default_listen_addr.parse().unwrap())
}

pub fn config_socket(socket: &mut UdpSocket, _config: &Config) -> Result<(), Error> {
    socket.set_nonblocking(true).unwrap();

    #[cfg(target_os = "linux")]
    if let Some(fwmark) = _config.fwmark {
        debug!("set fwmark {}", fwmark);
        setsockopt(socket.as_raw_fd(), sockopt::Mark, &fwmark).unwrap();
    }
    Ok(())
}
#[allow(clippy::type_complexity)]
pub fn native_socket_factory() -> Box<dyn Fn(&Config, bool) -> Result<Socket, Error>> {
    let socket_factory = |config: &Config, wait_dns: bool| -> Result<Socket, Error> {
        let bind_addr = match config.listen_addr {
            Some(addr) => addr,
            None => choose_bind_addr(
                config
                    .server_addrs
                    .as_ref()
                    .unwrap()
                    .first()
                    .map(|v| build_server_addr(v))
                    .as_deref(),
                config,
                wait_dns,
            )?,
        };
        let mut socket = UdpSocket::bind(bind_addr).expect("listen address bind fail.");

        config_socket(&mut socket, config)?;

        Ok(Box::new(NativeSocket::new(socket)))
    };

    Box::new(socket_factory)
}

#[cfg(feature = "holepunch")]
#[allow(clippy::type_complexity)]
pub fn rndz_socket_factory() -> Box<dyn Fn(&Config, bool) -> Result<Socket, Error>> {
    let socket_factory = move |config: &Config, wait_dns: bool| -> Result<Socket, Error> {
        let rndz = config.rndz.as_ref().expect("rndz config not set");
        let server = rndz.server.as_ref().expect("rndz server not set");
        let id = rndz.local_id.as_ref().expect("rndz local id not set");
        let builder = || -> Result<RndzSocket, Error> {
            let mut socket = match rndz.svr_sk_builder {
                Some(ref builder) => {
                    RndzSocket::new_with_socket(server, id, builder(config, wait_dns)?)?
                }
                None => RndzSocket::new(server, id, config.listen_addr).map_err(|e| {
                    error!("create rndz socket fail");
                    e
                })?,
            };

            if let Some(ref remote_id) = rndz.remote_id {
                socket.connect(remote_id).map_err(|e| {
                    error!("rndz connect fail, {:}", e);
                    e
                })?;
            } else {
                socket.listen()?;
            }

            Ok(socket)
        };

        let mut socket = loop {
            match builder() {
                Err(e) => {
                    if wait_dns {
                        thread::sleep(config.reconnect_timeout);
                        continue;
                    }
                    Err(e)?
                }
                Ok(s) => break s,
            }
        };

        config_socket(&mut socket, config)?;

        Ok(Box::new(socket))
    };

    Box::new(socket_factory)
}

#[allow(clippy::type_complexity)]
pub fn config_socket_factory(
    _config: &Config,
) -> Box<dyn Fn(&Config, bool) -> Result<Socket, Error>> {
    #[cfg(not(feature = "holepunch"))]
    let socket_factory = native_socket_factory();

    #[cfg(feature = "holepunch")]
    let socket_factory = if _config.rndz.is_none() {
        native_socket_factory()
    } else {
        // _config.rebind = true;
        rndz_socket_factory()
    };

    socket_factory
}
