use crate::config::Config;
use crate::cryptor;
use crate::error::Error;
use clap::{App, Arg};
use ipnet::IpNet;
use log;
use std::net::IpAddr;
use std::result::Result;
use std::time::Duration;

const DEFAULT_CIPHER: &str = "aes-128";
const DEFAULT_MTU: i32 = 1300;
const DEFAULT_RECONNECT_TIMEOUT: i32 = 47;
const DEFAULT_KEEPALIVE_INTERVAL: i32 = 7;

pub(crate) fn parse(config: &mut Config) -> Result<(), Error> {
    let mtu_usage = format!(
        "-m, --mtu [mtu]             'set MTU size, default:{}'",
        DEFAULT_MTU
    );
    let type_usage = format!(
        "-t, --type [encryption_type]        'encryption type(aes-128, aes-256), default:{}'",
        DEFAULT_CIPHER
    );

    let reconnect_timeout = format!(
        "-R, --reconnect-timeo [N]           'maximum inactive time (seconds) before reconnect, default:{}'",
        DEFAULT_RECONNECT_TIMEOUT
        );

    let keepalive = format!(
        "-K, --keepalive [N]                 'seconds between keep-alive tests, default:{}'",
        DEFAULT_KEEPALIVE_INTERVAL
    );

    let matches = App::new("minivtun-rs")
        .version("0.1")
        .about("Mini virtual tunneller in non-standard protocol")
        .arg(Arg::from_usage("-l, --local [ip:port] 'local IP:port for server to listen'"))
        .arg(Arg::from_usage("-r, --remote [host:port]            'host:port of server to connect (brace with [] for bare IPv6)'"))
        .arg(Arg::from_usage("-n, --ifname [ifname]               'virtual interface name'"))
        .arg(Arg::from_usage(&mtu_usage))
        .arg(Arg::from_usage("-a, --ipv4-addr [tun_lip/prf_len]   'pointopoint IPv4 pair of the virtual interface'"))
        .arg(Arg::from_usage("-A, --ipv6-addr [tun_ip6/pfx_len]   IPv6 address/prefix length pair"))
        .arg(Arg::from_usage("-d, --daemon                        'run as daemon process'"))
        .arg(Arg::from_usage("-e, --key [encryption_key]          'shared password for data encryption'"))
        .arg(Arg::from_usage("-v, --route... [network/prefix[=gw]]  'attached IPv4/IPv6 route on this link, can be multiple'"))
        .arg(Arg::from_usage(&type_usage))
        .arg(Arg::from_usage(&reconnect_timeout))
        .arg(Arg::from_usage(&keepalive))
        .arg(Arg::from_usage("-T, --table [table_name]            'route table of the attached routes'"))
        .arg(Arg::from_usage("-M, --metric [metric]               'metric of attached routes'"))
        .get_matches();

    if let Some(local) = matches.value_of("local") {
        config.listen_addr = Some(
            local
                .parse()
                .map_err(|_| Error::InvalidArg("invalid listen address".into()))?,
        );
    }

    config.server_addr = matches.value_of("remote").map(Into::into);

    config.ifname = matches.value_of("ifname").or(Some("mv%d")).map(Into::into);
    config.mtu = match matches.value_of("mtu") {
        Some(v) => Some(
            v.parse()
                .map_err(|_| Error::InvalidArg("invalid mtu".into()))?,
        ),
        _ => Some(DEFAULT_MTU),
    };

    if let Some(addr4) = matches.value_of("ipv4-addr") {
        config.loc_tun_in = Some(
            addr4
                .parse()
                .map_err(|_| Error::InvalidArg("invalid local ipv4 address".into()))?,
        );
    }
    if let Some(addr6) = matches.value_of("ipv6-addr") {
        config.loc_tun_in6 = Some(
            addr6
                .parse()
                .map_err(|_| Error::InvalidArg("invalid local ipv6 address".into()))?,
        );
    }

    match (
        matches.value_of("type").or(Some(DEFAULT_CIPHER)),
        matches.value_of("key"),
    ) {
        (Some(t), Some(key)) => {
            let secret: std::ffi::OsString = key
                .parse()
                .map_err(|_| Error::InvalidArg("invalid encryption key".into()))?;

            config.cryptor = cryptor::Builder::new(secret.as_os_str(), t)
                .map_err(|_| Error::InvalidArg("invalid encryption type ".into()))?;
        }
        _ => {
            log::warn!("*** WARNING: Transmission will not be encrypted.");
        }
    }

    if matches.occurrences_of("daemon") > 0 {
        config.daemonize = Some(true);
    }

    if let Some(routes) = matches.values_of("route") {
        let f = || -> Result<(), Box<dyn std::error::Error>> {
            for r in routes {
                let mut parts = r.split("=");
                let net: IpNet = parts.next().unwrap().parse()?;
                let gw: Option<IpAddr> = match parts.next() {
                    Some(v) => Some(v.parse()?),
                    None => None,
                };

                config.routes.push((net, gw));
            }

            Ok(())
        };

        f().map_err(|_| Error::InvalidArg("invalid route".into()))?
    }

    config.keepalive_interval = match matches.value_of("keepalive") {
        Some(v) => Some(Duration::from_secs(
            v.parse()
                .map_err(|_| Error::InvalidArg("keepalive".into()))?,
        )),
        _ => Some(Duration::from_secs(DEFAULT_KEEPALIVE_INTERVAL as u64)),
    };

    config.reconnect_timeout = match matches.value_of("reconnect-timeo") {
        Some(v) => Some(Duration::from_secs(
            v.parse()
                .map_err(|_| Error::InvalidArg("reconnect-timeo".into()))?,
        )),
        _ => Some(Duration::from_secs(DEFAULT_RECONNECT_TIMEOUT as u64)),
    };

    config.table = matches.value_of("table").map(Into::into);
    config.metric = matches.value_of("metric").map(Into::into);

    Ok(())
}
