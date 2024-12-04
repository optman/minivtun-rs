use clap::{App, Arg};
use ipnet::IpNet;
#[cfg(feature = "holepunch")]
use minivtun::RndzConfig;
use minivtun::{cryptor, Config, Error};
use std::{net::IpAddr, result::Result, time::Duration};

const DEFAULT_CIPHER: &str = "aes-128";

pub(crate) fn parse(config: &mut Config) -> Result<(), Error> {
    let default_mtu = config.mtu.to_string();
    let default_reconnect_timeo = config.reconnect_timeout.as_secs().to_string();
    let default_rebind_timeo = config.rebind_timeout.as_secs().to_string();
    let default_keepalive_interval = config.keepalive_interval.as_secs().to_string();
    let default_client_timeo = config.client_timeout.as_secs().to_string();

    let app = App::new("minivtun-rs")
        .version(env!("CARGO_PKG_VERSION"))
        .about("Mini virtual tunneller in non-standard protocol")
        .arg(Arg::from_usage("-l, --local [ip:port] 'local IP:port for server to listen'"))
        .arg(Arg::from_usage("-r, --remote... [host:port]         'host:port of servers to connect (brace with [] for bare IPv6)'"))
        .arg(Arg::from_usage("-n, --ifname [ifname]               'virtual interface name'"))
        .arg(Arg::from_usage( "-m, --mtu [mtu]             'mtu size'").default_value(&default_mtu))
        .arg(Arg::from_usage("-a, --ipv4-addr [tun_lip/prf_len]   'pointopoint IPv4 pair of the virtual interface'"))
        .arg(Arg::from_usage("-A, --ipv6-addr [tun_ip6/pfx_len]   IPv6 address/prefix length pair"))
        .arg(Arg::from_usage("-d, --daemon                        'run as daemon process'"))
        .arg(Arg::from_usage("-e, --key [encryption_key]          'shared password for data encryption'"))
        .arg(Arg::from_usage("-v, --route... [network/prefix[=gw]]  'attached IPv4/IPv6 route on this link, can be multiple'"))
        .arg(Arg::from_usage("-t, --type [encryption_type]        'encryption type'").default_value(DEFAULT_CIPHER).possible_values(&["plain", "aes-128", "aes-256"]))
        .arg(Arg::from_usage("-R, --reconnect-timeo [N]           'maximum inactive time (seconds) before reconnect'").default_value(&default_reconnect_timeo))
        .arg(Arg::from_usage("    --rebind-timeo [N]              'maximum time (seconds) before rebind'").default_value(&default_rebind_timeo))
        .arg(Arg::from_usage("    --client-timeo [N]              'maximum inactive time (seconds) before client timeout'").default_value(&default_client_timeo))
        .arg(Arg::from_usage("-K, --keepalive [N]                 'seconds between keep-alive tests'")
            .default_value(&default_keepalive_interval))
        .arg(Arg::from_usage("-T, --table [table_name]            'route table of the attached routes'"))
        .arg(Arg::from_usage("-M, --metric [metric]               'metric of attached routes'"))
        .arg(Arg::from_usage("-F, --fwmark [fwmark_num]           'fwmark set on vpn traffic'"))
        .arg(Arg::from_usage("-w, --wait-dns                      'wait for DNS resolve ready after service started'"))
        .arg(Arg::from_usage("    --rebind                        'rebind socket before reconnect'"))
        .arg(Arg::from_usage("-i, --info                          'view current tunnel info"))
        ;
    #[cfg(feature = "holepunch")]
    let app = {
        app.arg(Arg::from_usage(
            "--rndz-server [rndz_server]         'rndz server address'",
        ))
        .arg(Arg::from_usage(
            "--rndz-local-id [rndz_local_id]     'rndz local id'",
        ))
        .arg(Arg::from_usage(
            "--rndz-remote-id [rndz_remote_id]   'rndz remote id'",
        ))
    };

    let matches = app.get_matches();

    if let Some(local) = matches.value_of("local") {
        config.listen_addr = Some(
            local
                .parse()
                .map_err(|_| Error::InvalidArg("invalid listen address".into()))?,
        );
    }

    if let Some(addrs) = matches.values_of("remote") {
        config.server_addrs = Some(addrs.map(String::from).collect());
    }

    #[cfg(feature = "holepunch")]
    if matches.is_present("rndz-server") {
        config.rndz = Some(RndzConfig {
            server: matches
                .value_of("rndz-server")
                .expect("rndz server must be present")
                .to_owned(),
            local_id: matches
                .value_of("rndz-local-id")
                .expect("rndz-local-id must be present")
                .to_owned(),
            remote_id: matches.value_of("rndz-remote-id").map(Into::into),
        });
    }

    config.ifname = Some(matches.value_of("ifname").unwrap_or("mv%d").into());

    if let Some(v) = matches.value_of("mtu") {
        config.mtu = v
            .parse()
            .map_err(|_| Error::InvalidArg("invalid mtu".into()))?;
    }

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

    if let (Some(t), Some(key)) = (matches.value_of("type"), matches.value_of("key")) {
        config.cryptor = cryptor::Builder::new(key, t)
            .map_err(|_| Error::InvalidArg("invalid encryption type".into()))?
            .build();
    }

    config.daemonize = matches.is_present("daemon");

    if let Some(routes) = matches.values_of("route") {
        for r in routes {
            let mut parts = r.splitn(2, '=');
            let net: IpNet = parts
                .next()
                .ok_or(Error::InvalidArg("Invalid route network".into()))?
                .parse()
                .map_err(|_| Error::InvalidArg("invalid route".into()))?;
            let gw: Option<IpAddr> = parts
                .next()
                .map(|gw| {
                    gw.parse()
                        .map_err(|_| Error::InvalidArg("invalid gateway".into()))
                })
                .transpose()?;
            config.routes.push((net, gw));
        }
    }

    if let Some(v) = matches.value_of("keepalive") {
        config.keepalive_interval = Duration::from_secs(
            v.parse()
                .map_err(|_| Error::InvalidArg("keepalive".into()))?,
        );
    }

    if let Some(v) = matches.value_of("reconnect-timeo") {
        config.reconnect_timeout = Duration::from_secs(
            v.parse()
                .map_err(|_| Error::InvalidArg("reconnect-timeo".into()))?,
        );
    }

    if let Some(v) = matches.value_of("rebind-timeo") {
        config.rebind_timeout = Duration::from_secs(
            v.parse()
                .map_err(|_| Error::InvalidArg("rebind-timeo".into()))?,
        );
    }

    if let Some(v) = matches.value_of("client-timeo") {
        config.client_timeout = Duration::from_secs(
            v.parse()
                .map_err(|_| Error::InvalidArg("client-timeo".into()))?,
        );
    }

    config.table = matches.value_of("table").map(Into::into);
    config.metric = matches.value_of("metric").map(Into::into);

    if let Some(fwmark) = matches.value_of("fwmark") {
        config.fwmark = Some(
            fwmark
                .parse()
                .map_err(|_| Error::InvalidArg("invalid fwmark".into()))?,
        );
    }

    config.wait_dns = matches.is_present("wait-dns");
    config.rebind = matches.is_present("rebind");
    config.info = matches.is_present("info");

    Ok(())
}
