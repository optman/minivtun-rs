use crate::*;

mod native;
use native::NativeSocketFactory;

#[cfg(feature = "holepunch")]
mod rndz;

use std::os::fd::AsRawFd;
use std::rc::Rc;

#[allow(unused_imports)]
use std::os::fd::RawFd;

#[cfg(feature = "holepunch")]
pub use ::rndz::udp::SocketConfigure;

#[cfg(not(feature = "holepunch"))]
pub trait SocketConfigure {
    fn config_socket(&self, sk: RawFd) -> Result<(), std::io::Error>;
}

pub trait SocketFactory {
    fn create_socket(&self, server_addrs: Option<Vec<String>>) -> Result<Box<Socket>, Error>;
}

struct DefualtSocketFactory {
    #[cfg(feature = "holepunch")]
    config: Rc<Config>,
    sk_cfg: Option<Rc<Box<dyn SocketConfigure>>>,
    native: NativeSocketFactory,
    #[cfg(feature = "holepunch")]
    rndz: rndz::RndzSocketFacoty,
}
impl SocketFactory for DefualtSocketFactory {
    fn create_socket(&self, server_addrs: Option<Vec<String>>) -> Result<Box<Socket>, Error> {
        #[cfg(feature = "holepunch")]
        let socket = if self.config.rndz.is_some() {
            self.rndz.create_socket(server_addrs)?
        } else {
            self.native.create_socket(server_addrs)?
        };
        #[cfg(not(feature = "holepunch"))]
        let socket = self.native.create_socket(server_addrs)?;

        if let Some(ref sk_cfg) = self.sk_cfg {
            sk_cfg.config_socket(socket.as_raw_fd())?;
        }

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

    let sk_cfg = sk_cfg.map(Into::into);

    #[cfg(feature = "holepunch")]
    let rndz = rndz::RndzSocketFacoty {
        config: config.clone(),
        sk_cfg: sk_cfg.clone(),
    };

    Box::new(DefualtSocketFactory {
        #[cfg(feature = "holepunch")]
        config,
        #[cfg(feature = "holepunch")]
        rndz,
        native,
        sk_cfg,
    })
}

#[cfg(target_os = "linux")]
pub fn default_socket_configure(config: Rc<Config>) -> Option<Box<dyn SocketConfigure>> {
    Some(Box::new(linux::DefaultSocketConfig {
        config: config.clone(),
    }))
}
#[cfg(not(target_os = "linux"))]
pub fn default_socket_configure(_: Rc<Config>) -> Option<Box<dyn SocketConfigure>> {
    None
}

#[cfg(target_os = "linux")]
mod linux {
    use crate::{Config, SocketConfigure};
    use nix::sys::socket::{setsockopt, sockopt};
    use std::os::fd::BorrowedFd;
    use std::rc::Rc;
    pub(crate) struct DefaultSocketConfig {
        pub(crate) config: Rc<Config>,
    }
    impl SocketConfigure for DefaultSocketConfig {
        fn config_socket(&self, sk: std::os::unix::prelude::RawFd) -> std::io::Result<()> {
            if let Some(fwmark) = self.config.fwmark {
                log::debug!("set fwmark {}", fwmark);
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
}
