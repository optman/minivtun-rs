use crate::cryptor;
use crate::error::Error;
use crate::socket::Socket;
#[cfg(feature = "holepunch")]
use crate::RndzConfig;

use ipnet::IpNet;
use ipnet::{Ipv4Net, Ipv6Net};
use std::net::{IpAddr, SocketAddr};
use std::os::unix::prelude::RawFd;
use std::time::Duration;

const DEFAULT_MTU: i32 = 1300;
const DEFAULT_RECONNECT_TIMEOUT: i32 = 47;
const DEFAULT_KEEPALIVE_INTERVAL: i32 = 7;

//https://doc.rust-lang.org/beta/unstable-book/language-features/trait-alias.html
//
//pub trait SocketFactory= Fn(&Config) -> Result<Socket, Error>;

#[derive(Default)]
pub struct Config<'a> {
    #[allow(clippy::type_complexity)]
    pub(crate) socket_factory: Option<&'a dyn Fn(&Config) -> Result<Socket, Error>>,
    pub(crate) socket: Option<Socket>,
    pub(crate) tun_fd: RawFd,
    pub(crate) control_fd: Option<RawFd>,
    pub ifname: Option<String>,
    pub mtu: i32,
    pub loc_tun_in: Option<Ipv4Net>,
    pub loc_tun_in6: Option<Ipv6Net>,
    pub listen_addr: Option<SocketAddr>,
    pub server_addr: Option<String>,
    pub cryptor: Option<Box<dyn cryptor::Cryptor>>,
    pub daemonize: bool,
    pub routes: Vec<(IpNet, Option<IpAddr>)>,
    pub keepalive_interval: Duration,
    pub reconnect_timeout: Duration,
    pub table: Option<String>,
    pub metric: Option<String>,
    pub fwmark: Option<u32>,
    pub wait_dns: bool,
    pub rebind: bool,
    #[cfg(feature = "holepunch")]
    pub rndz: Option<RndzConfig<'a>>,
}

impl<'a> Config<'a> {
    pub fn new() -> Config<'a> {
        Config {
            keepalive_interval: Duration::from_secs(DEFAULT_KEEPALIVE_INTERVAL as u64),
            reconnect_timeout: Duration::from_secs(DEFAULT_RECONNECT_TIMEOUT as u64),
            mtu: DEFAULT_MTU,
            ..Default::default()
        }
    }

    pub fn with_socket(&mut self, s: Socket) -> &mut Self {
        self.socket = Some(s);
        self
    }

    pub fn with_tun_fd(&mut self, fd: RawFd) -> &mut Self {
        self.tun_fd = fd;
        self
    }

    #[allow(clippy::type_complexity)]
    pub fn with_socket_factory(
        &mut self,
        f: &'a dyn Fn(&Config) -> Result<Socket, Error>,
    ) -> &mut Self {
        self.socket_factory = Some(f);
        self
    }

    pub fn with_control_fd(&mut self, fd: RawFd) -> &mut Self {
        self.control_fd = Some(fd);
        self
    }

    pub fn with_server_addr(&mut self, addr: String) -> &mut Self {
        self.server_addr = Some(addr);
        self
    }

    pub fn with_ip_addr(&mut self, addr: IpNet) -> &mut Self {
        match addr {
            IpNet::V4(addr) => self.loc_tun_in = Some(addr),
            IpNet::V6(addr) => self.loc_tun_in6 = Some(addr),
        }
        self
    }

    pub fn with_cryptor(&mut self, cryptor: Option<Box<dyn cryptor::Cryptor>>) -> &mut Self {
        self.cryptor = cryptor;
        self
    }

    #[allow(clippy::type_complexity)]
    pub fn socket_factory(&self) -> &Option<&'_ dyn Fn(&Config) -> Result<Socket, Error>> {
        &self.socket_factory
    }
}

#[cfg(test)]
mod tests {

    use self::super::*;

    #[test]
    fn test() {
        Config::default();
    }
}
