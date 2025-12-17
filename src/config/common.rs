#[cfg(feature = "holepunch")]
use crate::config::rndz;
use crate::cryptor;
use crate::util::build_server_addr;

use ipnet::IpNet;
use ipnet::{Ipv4Net, Ipv6Net};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

const DEFAULT_MTU: u16 = 1300;
const DEFAULT_RECONNECT_TIMEOUT: Duration = Duration::from_secs(60 * 10);
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
    pub rndz: Option<rndz::Config>,
    pub info: bool,
    pub change_server: bool,
    pub pre_resolve_dns: bool,
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
        self.server_addrs.get_or_insert_with(Vec::new).push(addr);
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
    pub fn rndz(&self) -> Option<&rndz::Config> {
        self.rndz.as_ref()
    }

    pub fn cryptor(&self) -> Option<&dyn cryptor::Cryptor> {
        self.cryptor.as_deref()
    }

    #[cfg(feature = "holepunch")]
    pub fn is_holepunch(&self) -> bool {
        self.rndz.is_some()
    }

    pub fn is_client(&self) -> bool {
        #[cfg(not(feature = "holepunch"))]
        {
            self.server_addrs.is_some()
        }

        #[cfg(feature = "holepunch")]
        {
            self.server_addrs.is_some()
                || self.rndz.as_ref().is_some_and(|c| c.remote_id.is_some())
        }
    }

    pub fn get_server_addrs(&self) -> Option<Vec<String>> {
        #[cfg(not(feature = "holepunch"))]
        {
            self.server_addrs.clone()
        }

        #[cfg(feature = "holepunch")]
        {
            self.server_addrs
                .clone()
                .or_else(|| self.rndz.as_ref().map(|rndz| rndz.servers.clone()))
                .map(|mut addrs| addrs.iter_mut().map(|s| build_server_addr(s)).collect())
        }
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
