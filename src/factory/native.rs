use crate::{util::build_server_addr, Config, Error, NativeSocket, Socket, SocketFactory};
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::rc::Rc;

pub fn choose_bind_addr(server_addr: Option<&str>, config: &Config) -> Result<SocketAddr, Error> {
    let server_addr: Option<SocketAddr> = match server_addr {
        Some(ref server_addr) => loop {
            let addrs = server_addr.to_socket_addrs().map_err(|_| {
                Error::InvalidArg(format!("invalid remote addr or dns fail {:?}", server_addr))
            });

            match addrs {
                Ok(mut addrs) => break addrs.next(),
                Err(err) => {
                    if config.wait_dns {
                        log::info!("wait dns");
                        std::thread::sleep(config.reconnect_timeout);
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

pub(crate) struct NativeSocketFactory {
    pub(crate) config: Rc<Config>,
}
impl SocketFactory for NativeSocketFactory {
    fn create_socket(&self) -> Result<Box<Socket>, Error> {
        let config = &self.config;
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
            )?,
        };
        let socket = UdpSocket::bind(bind_addr).expect("listen address bind fail.");

        Ok(Box::new(NativeSocket::new(socket)))
    }
}
