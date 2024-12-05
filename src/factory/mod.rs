use crate::*;

mod native;
use native::NativeSocketFactory;

#[cfg(feature = "holepunch")]
mod rndz;

#[cfg(target_os = "linux")]
use nix::sys::socket::{setsockopt, sockopt};

use std::os::fd::AsRawFd;
use std::rc::Rc;

#[allow(unused_imports)]
use std::os::fd::{BorrowedFd, RawFd};

#[cfg(feature = "holepunch")]
pub use ::rndz::udp::SocketConfigure;

#[cfg(not(feature = "holepunch"))]
pub trait SocketConfigure {
    fn config_socket(&self, sk: RawFd) -> Result<(), std::io::Error>;
}

pub trait SocketFactory {
    fn create_socket(&self) -> Result<Box<Socket>, Error>;
}

struct DefualtSocketFactory {
    #[cfg(feature = "holepunch")]
    config: Rc<Config>,
    sk_cfg: Rc<Box<dyn SocketConfigure>>,
    native: NativeSocketFactory,
    #[cfg(feature = "holepunch")]
    rndz: rndz::RndzSocketFacoty,
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
    let rndz = rndz::RndzSocketFacoty {
        config: config.clone(),
        sk_cfg: Some(sk_cfg.clone()),
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

struct DefaultSocketConfig {
    #[allow(dead_code)]
    config: Rc<Config>,
}
impl SocketConfigure for DefaultSocketConfig {
    #[allow(unused_variables)]
    fn config_socket(&self, sk: std::os::unix::prelude::RawFd) -> std::io::Result<()> {
        #[cfg(target_os = "linux")]
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
