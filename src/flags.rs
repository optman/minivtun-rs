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
    let default_mtu = DEFAULT_MTU.to_string();
    let default_reconnect_timeo = DEFAULT_RECONNECT_TIMEOUT.to_string();
    let default_keepalive_interval = DEFAULT_KEEPALIVE_INTERVAL.to_string();

    let matches = App::new("minivtun-rs")
        .version(env!("CARGO_PKG_VERSION"))
        .about("Mini virtual tunneller in non-standard protocol")
        .arg(Arg::from_usage("-l, --local [ip:port] 'local IP:port for server to listen'"))
        .arg(Arg::from_usage("-r, --remote [host:port]            'host:port of server to connect (brace with [] for bare IPv6)'"))
        .arg(Arg::from_usage("--rndz-server [rndz_server]         'rndz server address"))
        .arg(Arg::from_usage("--rndz-id [rndz_id]                 'my rndz id"))
        .arg(Arg::from_usage("--rndz-remote-id [rndz_remote_id]   'remote rndz id"))
        .arg(Arg::from_usage("-n, --ifname [ifname]               'virtual interface name'"))
        .arg(Arg::from_usage( "-m, --mtu [mtu]             'mtu size'").default_value(&default_mtu))
        .arg(Arg::from_usage("-a, --ipv4-addr [tun_lip/prf_len]   'pointopoint IPv4 pair of the virtual interface'"))
        .arg(Arg::from_usage("-A, --ipv6-addr [tun_ip6/pfx_len]   IPv6 address/prefix length pair"))
        .arg(Arg::from_usage("-d, --daemon                        'run as daemon process'"))
        .arg(Arg::from_usage("-e, --key [encryption_key]          'shared password for data encryption'"))
        .arg(Arg::from_usage("-v, --route... [network/prefix[=gw]]  'attached IPv4/IPv6 route on this link, can be multiple'"))
        .arg(Arg::from_usage("-t, --type [encryption_type]        'encryption type'").default_value(DEFAULT_CIPHER).possible_values(&["plain", "aes-128", "aes-256"]))
        .arg(Arg::from_usage("-R, --reconnect-timeo [N]           'maximum inactive time (seconds) before reconnect'").default_value(&default_reconnect_timeo))
        .arg(Arg::from_usage("-K, --keepalive [N]                 'seconds between keep-alive tests'")
            .default_value(&default_keepalive_interval))
        .arg(Arg::from_usage("-T, --table [table_name]            'route table of the attached routes'"))
        .arg(Arg::from_usage("-M, --metric [metric]               'metric of attached routes'"))
        .arg(Arg::from_usage("-F, --fwmark [fwmark_num]           'fwmark set on vpn traffic'"))
        .get_matches();

    if let Some(local) = matches.value_of("local") {
        config.listen_addr = Some(
            local
                .parse()
                .map_err(|_| Error::InvalidArg("invalid listen address".into()))?,
        );
    }

    config.server_addr = matches.value_of("remote").map(Into::into);

    config.rndz_server = matches.value_of("rndz-server").map(Into::into);
    config.rndz_id = matches.value_of("rndz-id").map(Into::into);
    config.rndz_remote_id = matches.value_of("rndz-remote-id").map(Into::into);

    if config.rndz_server.is_some() && config.rndz_id.is_none() {
        Err(Error::InvalidArg("rndz_id not set".into()))?;
    }

    if config.server_addr.is_some() && config.rndz_remote_id.is_some() {
        Err(Error::InvalidArg(
            "can't set both server_addr and rndz_remote_id".into(),
        ))?;
    }

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
            config.cryptor = cryptor::Builder::new(key, t)
                .map_err(|_| Error::InvalidArg("invalid encryption type ".into()))?;
        }
        _ => {
            log::warn!("*** WARNING: Transmission will not be encrypted.");
        }
    }

    if matches.is_present("daemon") {
        config.daemonize = Some(true);
    }

    if let Some(routes) = matches.values_of("route") {
        let f = || -> Result<(), Box<dyn std::error::Error>> {
            for r in routes {
                let mut parts = r.splitn(2, "=");
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

    if let Some(fwmark) = matches.value_of("fwmark") {
        config.fwmark = Some(
            fwmark
                .parse()
                .map_err(|_| Error::InvalidArg("invalid fwmark".into()))?,
        );
    };

    Ok(())
}
