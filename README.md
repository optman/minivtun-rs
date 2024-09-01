# minivtun-rs

A Rust implementation of [minivtun](https://github.com/rssnsj/minivtun), with hole punching supported by [rndz](https://github.com/optman/rndz).

## Table of Contents
- [Introduction](#introduction)
- [Features](#features)
- [Usage](#usage)
- [Quick Start](#quick-start)
- [Hole Punching Setup Example](#hole-punching-setup-example)
- [Building](#building)
- [Contributing](#contributing)
- [License](#license)

## Introduction

`minivtun-rs` is a lightweight, minimalistic virtual tunneller written in Rust. It is designed to provide a simple and efficient solution for creating virtual network interfaces and tunnels, supporting both IPv4 and IPv6.

## Features

- Daemon mode for background operation
- IPv4 and IPv6 support
- Configurable keepalive mechanism
- Data encryption with various options
- Hole punching support via `rndz`

## Usage

```
minivtun-rs 0.1.5
Mini virtual tunneller in non-standard protocol

USAGE:
    minivtun-rs [FLAGS] [OPTIONS]

FLAGS:
    -d, --daemon      run as daemon process
    -h, --help        Prints help information
    -i, --info        view current tunnel inf
        --rebind      rebind socket before reconnect
    -V, --version     Prints version information
    -w, --wait-dns    wait for DNS resolve ready after service started

OPTIONS:
        --client-timeo <N>                   maximum inactive time (seconds) before client timeout [default: 120]
    -F, --fwmark <fwmark_num>                fwmark set on vpn traffic
    -n, --ifname <ifname>                    virtual interface name
    -a, --ipv4-addr <tun_lip/prf_len>        pointopoint IPv4 pair of the virtual interface
    -A, --ipv6-addr <tun_ip6/pfx_len>
    -K, --keepalive <N>                      seconds between keep-alive tests [default: 7]
    -e, --key <encryption_key>               shared password for data encryption
    -l, --local <ip:port>                    local IP:port for server to listen
    -M, --metric <metric>                    metric of attached routes
    -m, --mtu <mtu>                          mtu size [default: 1300]
    -R, --reconnect-timeo <N>                maximum inactive time (seconds) before reconnect [default: 47]
    -r, --remote <host:port>                 host:port of server to connect (brace with [] for bare IPv6)
        --rndz-local-id <rndz_local_id>      rndz local id
        --rndz-remote-id <rndz_remote_id>    rndz remote id
        --rndz-server <rndz_server>          rndz server address
    -v, --route <network/prefix[=gw>...      attached IPv4/IPv6 route on this link, can be multiple
    -T, --table <table_name>                 route table of the attached routes
    -t, --type <encryption_type>             encryption type [default: aes-128]  [possible values: plain, aes-128, aes-
                                             256]

```

## Quick Start

### Server

```
minivtun-rs -l 0.0.0.0:1234 -a 10.0.0.1/24 -e helloworld
```

### Client

```
minivtun-rs -r {SERVERADDR}:1234 -a 10.0.0.2/24 -e helloworld
```

### View Status

```
minivtun-rs -i
```

## Hole Punching Setup Example

### Server

```
minivtun-rs --rndz_server rndz.optman.net:8888 --rndz-local-id {SERVERNAME}  -a 10.0.0.1/24 -e helloworld
```

### Client

```
minivtun-rs --rndz_server rndz.optman.net:8888 --rndz-remote-id {SERVERNAME} --rndz-local-id {LOCALNAME} -a 10.0.0.2/24 -e helloworld
```

## Building

Ensure you have Rust installed. Then, clone the repository and build the project:

```
git clone https://github.com/optman/minivtun-rs.git
cd minivtun-rs
cargo build --release
```

## Contributing

Contributions are welcome! Please open an issue or submit a pull request for any enhancements or bug fixes.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.