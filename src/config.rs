use crate::cryptor;
#[cfg(feature = "holepunch")]
use crate::RndzConfig;

use ipnet::IpNet;
use ipnet::{Ipv4Net, Ipv6Net};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

const DEFAULT_MTU: u16 = 1300;
const DEFAULT_RECONNECT_TIMEOUT: Duration = Duration::from_secs(47);
const DEFAULT_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(7);
const DEFAULT_CLIENT_TIMEOUT: Duration = Duration::from_secs(120);
const DEFAULT_REBIND_TIMEOUT: Duration = Duration::from_secs(60 * 30);

#[derive(Default)]
pub struct Config {
    pub ifname: Option<String>,
    pub mtu: u16,
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
    pub rndz: Option<RndzConfig>,
    pub info: bool,
}

impl Config {
    pub fn new() -> Config {
        Config {
            keepalive_interval: DEFAULT_KEEPALIVE_INTERVAL,
            reconnect_timeout: DEFAULT_RECONNECT_TIMEOUT,
            rebind_timeout: DEFAULT_REBIND_TIMEOUT,
            client_timeout: DEFAULT_CLIENT_TIMEOUT,
            mtu: DEFAULT_MTU,
            ..Default::default()
        }
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

    #[cfg(feature = "holepunch")]
    pub fn rndz(&self) -> Option<&RndzConfig> {
        self.rndz.as_ref()
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
