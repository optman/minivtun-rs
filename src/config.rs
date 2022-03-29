use crate::cryptor::Builder;
use ipnet::IpNet;
use ipnet::{Ipv4Net, Ipv6Net};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

#[derive(Clone, Default)]
pub struct Config {
    pub ifname: Option<String>,
    pub mtu: Option<i32>,
    pub loc_tun_in: Option<Ipv4Net>,
    pub loc_tun_in6: Option<Ipv6Net>,
    pub listen_addr: Option<SocketAddr>,
    pub server_addr: Option<String>,
    pub cryptor: Builder,
    pub daemonize: Option<bool>,
    pub routes: Vec<(IpNet, Option<IpAddr>)>,
    pub keepalive_interval: Option<Duration>,
    pub reconnect_timeout: Option<Duration>,
    pub table: Option<String>,
    pub metric: Option<String>,
    pub fwmark: Option<u32>,
    pub rndz_server: Option<String>,
    pub rndz_id: Option<String>,
    pub rndz_remote_id: Option<String>,
}

#[cfg(test)]
mod tests {

    use self::super::*;

    #[test]
    fn test() {
        Config::default();
    }
}
