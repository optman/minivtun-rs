use crate::*;
#[cfg(target_os = "linux")]
use log::debug;
#[cfg(target_os = "linux")]
use nix::sys::socket::{setsockopt, sockopt};

use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::os::fd::{AsRawFd, BorrowedFd};
use std::rc::Rc;
use std::thread;
use util::build_server_addr;

#[cfg(feature = "holepunch")]
pub use rndz::udp::SocketConfigure;

#[cfg(not(feature = "holepunch"))]
pub trait SocketConfigure {
    fn config_socket(&self, sk: RawFd) -> Result<()>;
}

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

pub trait SocketFactory {
    fn create_socket(&self) -> Result<Box<Socket>, Error>;
}

struct NativeSocketFactory {
    config: Rc<Config>,
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

#[cfg(feature = "holepunch")]
struct SharedSocketConfigure {
    sk_cfg: Rc<Box<dyn SocketConfigure>>,
}

#[cfg(feature = "holepunch")]
impl SocketConfigure for SharedSocketConfigure {
    fn config_socket(&self, sk: std::os::unix::prelude::RawFd) -> std::io::Result<()> {
        self.sk_cfg.config_socket(sk)
    }
}

#[cfg(feature = "holepunch")]
struct RndzSocketFacoty {
    config: Rc<Config>,
    sk_cfg: Option<Rc<Box<dyn SocketConfigure>>>,
}

#[cfg(feature = "holepunch")]
impl SocketFactory for RndzSocketFacoty {
    fn create_socket(&self) -> Result<Box<Socket>, Error> {
        let config = &self.config;
        let rndz = config.rndz.as_ref().expect("rndz config not set");
        let server = &rndz.server;
        let id = &rndz.local_id;
        let builder = || -> Result<RndzSocket, Error> {
            let sk_cfg = self.sk_cfg.clone().map(|sk_cfg| {
                let sk_cfg = SharedSocketConfigure { sk_cfg };
                Box::new(sk_cfg) as Box<dyn SocketConfigure>
            });

            let mut socket =
                RndzSocket::new(server, id, config.listen_addr, sk_cfg).inspect_err(|e| {
                    log::error!("create rndz socket fail, {:?}", e);
                })?;

            if let Some(ref remote_id) = rndz.remote_id {
                socket.connect(remote_id).inspect_err(|e| {
                    log::error!("rndz connect fail, {:}", e);
                })?;
            } else {
                socket.listen()?;
            }

            Ok(socket)
        };

        let socket = loop {
            match builder() {
                Err(e) => {
                    if config.wait_dns {
                        log::info!("wait dns?");
                        thread::sleep(config.reconnect_timeout);
                        continue;
                    }
                    Err(e)?
                }
                Ok(s) => break s,
            }
        };

        Ok(Box::new(socket))
    }
}

#[cfg(feature = "holepunch")]
struct DefualtSocketFactory {
    config: Rc<Config>,
    sk_cfg: Rc<Box<dyn SocketConfigure>>,
    native: NativeSocketFactory,
    #[cfg(feature = "holepunch")]
    rndz: RndzSocketFacoty,
}
impl SocketFactory for DefualtSocketFactory {
    fn create_socket(&self) -> Result<Box<Socket>, Error> {
        #[cfg(feature = "holepunch")]
        let socket = if self.config.rndz.is_some() {
            self.rndz.create_socket()?
        } else {
            self.native.create_socket()?
        };
        #[cfg(not(feature = "holepunch"))]
        let socket = self.native.create_socket()?;

        self.sk_cfg.config_socket(socket.as_raw_fd())?;

        socket.set_nonblocking(true).unwrap();

        Ok(socket)
    }
}

pub fn default_socket_factory(
    config: Rc<Config>,
    sk_cfg: Option<Box<dyn SocketConfigure>>,
) -> Box<dyn SocketFactory> {
    let native = NativeSocketFactory {
        config: config.clone(),
    };

    let sk_cfg: Box<dyn SocketConfigure> = sk_cfg.unwrap_or_else(|| {
        Box::new(DefaultSocketConfig {
            config: config.clone(),
        })
    });

    let sk_cfg = Rc::new(sk_cfg);

    #[cfg(feature = "holepunch")]
    let rndz = RndzSocketFacoty {
        config: config.clone(),
        sk_cfg: Some(sk_cfg.clone()),
    };

    Box::new(DefualtSocketFactory {
        config,
        #[cfg(feature = "holepunch")]
        rndz,
        native,
        sk_cfg,
    })
}

struct DefaultSocketConfig {
    config: Rc<Config>,
}
impl SocketConfigure for DefaultSocketConfig {
    fn config_socket(&self, sk: std::os::unix::prelude::RawFd) -> std::io::Result<()> {
        #[cfg(target_os = "linux")]
        if let Some(fwmark) = self.config.fwmark {
            debug!("set fwmark {}", fwmark);
            setsockopt(
                unsafe { &BorrowedFd::borrow_raw(sk) },
                sockopt::Mark,
                &fwmark,
            )
            .map_err(std::io::Error::other)?;
        }

        Ok(())
    }
}
