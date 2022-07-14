use crate::cryptor;
use ipnet::IpNet;
use ipnet::{Ipv4Net, Ipv6Net};
use std::net::{IpAddr, SocketAddr};
use std::rc::Rc;
use std::time::Duration;

#[derive(Default)]
pub struct Config {
    pub ifname: Option<String>,
    pub mtu: Option<i32>,
    pub loc_tun_in: Option<Ipv4Net>,
    pub loc_tun_in6: Option<Ipv6Net>,
    pub listen_addr: Option<SocketAddr>,
    pub server_addr: Option<String>,
    pub cryptor: Option<Rc<Box<dyn cryptor::Cryptor>>>,
    pub daemonize: Option<bool>,
    pub routes: Vec<(IpNet, Option<IpAddr>)>,
    pub keepalive_interval: Option<Duration>,
    pub reconnect_timeout: Option<Duration>,
    pub table: Option<String>,
    pub metric: Option<String>,
    pub fwmark: Option<u32>,
    pub wait_dns: bool,
}

#[cfg(test)]
mod tests {

    use self::super::*;

    #[test]
    fn test() {
        Config::default();
    }
}
