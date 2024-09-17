use crate::cryptor;
use crate::error::Error;
use crate::socket::Socket;
#[cfg(feature = "holepunch")]
use crate::RndzConfig;

use ipnet::IpNet;
use ipnet::{Ipv4Net, Ipv6Net};
use std::net::{IpAddr, SocketAddr};
use std::os::unix::io::OwnedFd;
use std::os::unix::net::UnixListener;
use std::time::Duration;
use tun::platform::posix::Fd;

const DEFAULT_MTU: i32 = 1300;
const DEFAULT_RECONNECT_TIMEOUT: Duration = Duration::from_secs(47);
const DEFAULT_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(7);
const DEFAULT_CLIENT_TIMEOUT: Duration = Duration::from_secs(120);
const DEFAULT_REBIND_TIMEOUT: Duration = Duration::from_secs(60 * 30);

//https://doc.rust-lang.org/beta/unstable-book/language-features/trait-alias.html
//
//pub trait SocketFactory= Fn(&Config) -> Result<Socket, Error>;

#[derive(Default)]
pub struct Config<'a> {
    #[allow(clippy::type_complexity)]
    pub(crate) socket_factory: Option<&'a dyn Fn(&Config, bool) -> Result<Socket, Error>>,
    pub(crate) socket: Option<Socket>,
    pub(crate) tun_fd: Option<Fd>,
    pub(crate) control_fd: Option<UnixListener>,
    pub ifname: Option<String>,
    pub mtu: i32,
    pub loc_tun_in: Option<Ipv4Net>,
    pub loc_tun_in6: Option<Ipv6Net>,
    pub listen_addr: Option<SocketAddr>,
    pub server_addrs: Option<Vec<String>>,
    pub cryptor: Option<Box<dyn cryptor::Cryptor>>,
    pub daemonize: bool,
    pub routes: Vec<(IpNet, Option<IpAddr>)>,
    pub keepalive_interval: Duration,
    pub reconnect_timeout: Duration,
    pub rebind_timeout: Duration,
    pub client_timeout: Duration,
    pub table: Option<String>,
    pub metric: Option<String>,
    pub fwmark: Option<u32>,
    pub wait_dns: bool,
    pub rebind: bool,
    #[cfg(feature = "holepunch")]
    pub rndz: Option<RndzConfig<'a>>,
    pub info: bool,
    pub exit_signal: Option<OwnedFd>,
}

impl<'a> Config<'a> {
    pub fn new() -> Config<'a> {
        Config {
            keepalive_interval: DEFAULT_KEEPALIVE_INTERVAL,
            reconnect_timeout: DEFAULT_RECONNECT_TIMEOUT,
            rebind_timeout: DEFAULT_REBIND_TIMEOUT,
            client_timeout: DEFAULT_CLIENT_TIMEOUT,
            mtu: DEFAULT_MTU,
            ..Default::default()
        }
    }

    pub fn with_socket(&mut self, s: Socket) -> &mut Self {
        self.socket = Some(s);
        self
    }

    pub fn with_tun_fd(&mut self, fd: Fd) -> &mut Self {
        self.tun_fd = Some(fd);
        self
    }

    #[allow(clippy::type_complexity)]
    pub fn with_socket_factory(
        &mut self,
        f: &'a dyn Fn(&Config, bool) -> Result<Socket, Error>,
    ) -> &mut Self {
        self.socket_factory = Some(f);
        self
    }

    pub fn with_control_fd(&mut self, fd: UnixListener) -> &mut Self {
        self.control_fd = Some(fd);
        self
    }

    pub fn with_server_addr(&mut self, addr: String) -> &mut Self {
        if self.server_addrs.is_none() {
            self.server_addrs = Some(Vec::new());
        }
        self.server_addrs.as_mut().unwrap().push(addr);
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
    pub fn socket_factory(&self) -> &Option<&'_ dyn Fn(&Config, bool) -> Result<Socket, Error>> {
        &self.socket_factory
    }

    pub fn with_exit_signal(&mut self, exit_signal: OwnedFd) -> &mut Self {
        self.exit_signal = Some(exit_signal);
        self
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
