# minivtun-rs
A Rust implementation of minivtun.

###Usage
minivtun-rs 0.1
Mini virtual tunneller in non-standard protocol

USAGE:
    minivtun-rs [FLAGS] [OPTIONS]

FLAGS:
    -d, --daemon     run as daemon process
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -n, --ifname <ifname>                  virtual interface name
    -a, --ipv4-addr <tun_lip/prf_len>      pointopoint IPv4 pair of the virtual interface
    -A, --ipv6-addr <tun_ip6/pfx_len>
    -K, --keepalive <N>                    seconds between keep-alive tests, default:7
    -e, --key <encryption_key>             shared password for data encryption
    -l, --local <ip:port>                  local IP:port for server to listen
    -M, --metric <metric>                  metric of attached routes
    -m, --mtu <mtu>                        set MTU size, default:1300
    -R, --reconnect-timeo <N>              maximum inactive time (seconds) before reconnect, default:47
    -r, --remote <host:port>               host:port of server to connect (brace with [] for bare IPv6)
    -v, --route <network/prefix[=gw>...    attached IPv4/IPv6 route on this link, can be multiple
    -T, --table <table_name>               route table of the attached routes
    -t, --type <encryption_type>           encryption type(aes-128, aes-256), default:aes-128


