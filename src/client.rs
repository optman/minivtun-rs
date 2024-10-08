use crate::config::Config;
use crate::msg;
use crate::poll;
use crate::{
    error::Error,
    msg::Op,
    msg::{builder::Builder, ipdata, ipdata::Kind},
    socket::Socket,
    state::State,
    util::build_server_addr,
};
use log::{debug, info, trace, warn};
use size::Size;
use std::fmt::{Display, Formatter};
use std::io::{Read, Write};
use std::mem::MaybeUninit;
use std::os::unix::io::FromRawFd;
use std::os::unix::io::{AsRawFd, RawFd};
use std::os::unix::net::UnixListener;
use std::os::unix::net::UnixStream;
use std::time::Instant;
use tun::platform::posix::Fd;

extern crate libc;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub struct Client<'a> {
    config: Config<'a>,
    socket: Socket,
    state: State,
    tun: Fd,
    control_fd: Option<UnixListener>,
    server_index: usize,
}

impl<'a> Client<'a> {
    pub fn new(mut config: Config<'a>) -> Result<Self> {
        let socket = config.socket.take().map_or_else(
            || {
                config
                    .socket_factory
                    .as_ref()
                    .expect("neither socket nor socket_factory is set")(
                    &config, config.wait_dns
                )
            },
            |v| Ok(v),
        )?;

        let tun = config
            .tun_fd
            .take()
            .ok_or_else(|| Error::InvalidArg("tun_fd not set".to_string()))?;

        let control_fd = config.control_fd.take();
        Ok(Self {
            config,
            socket,
            tun,
            control_fd,
            state: Default::default(),
            server_index: 0,
        })
    }

    pub fn run(mut self) -> Result<()> {
        if let Some(server_addr) = self
            .config
            .server_addrs
            .as_ref()
            .and_then(|addrs| addrs.get(self.server_index))
        {
            //ignore failure
            let _ = self
                .socket
                .connect(build_server_addr(server_addr))
                .map_err(|e| warn!("{:?}", e));
        }
        self.state.last_connect = Some(Instant::now());

        poll::poll(
            self.tun.as_raw_fd(),
            self.control_fd.as_ref().map(|v| v.as_raw_fd()),
            self.config.exit_signal.as_ref().map(|v| v.as_raw_fd()),
            self,
        )
    }

    fn forward_remote(&mut self, kind: Kind, pkt: &[u8]) -> Result<()> {
        self.state.tx_bytes += pkt.len() as u64;

        let buf = msg::Builder::default()
            .cryptor(&self.config.cryptor)?
            .seq(self.state.next_seq())?
            .ip_data()?
            .kind(kind)?
            .payload(pkt)?
            .build()?;

        //ignore failure
        let _ = self.socket.send(&buf);

        Ok(())
    }

    fn forward_local(&mut self, pkt: &[u8]) -> Result<()> {
        self.state.rx_bytes += pkt.len() as u64;

        match pkt[0] >> 4 {
            4 | 6 => {
                //ignore failure
                let _ = self.tun.write(pkt);
            }
            _ => debug!("[FWD]invalid packet!"),
        }

        Ok(())
    }

    fn send_echo(&mut self) -> Result<()> {
        let mut builder = msg::Builder::default()
            .cryptor(&self.config.cryptor)?
            .seq(self.state.next_seq())?
            .echo_req()?
            .id(self.state.gen_id())?;

        if let Some(ref addr4) = self.config.loc_tun_in {
            builder = builder.ipv4_addr(addr4.addr())?;
        }

        if let Some(ref addr6) = self.config.loc_tun_in6 {
            builder = builder.ipv6_addr(addr6.addr())?;
        }

        //ignore failure
        let _ = self.socket.send(builder.build()?.as_ref());

        Ok(())
    }
}

impl<'a> Display for Client<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        writeln!(f, "client mode")?;
        writeln!(
            f,
            "{:<15} {}",
            "server_addr:",
            self.socket
                .peer_addr()
                .map(|v| v.to_string())
                .unwrap_or_else(|_| "NA".to_string())
        )?;
        writeln!(
            f,
            "{:<15} {}",
            "local_addr:",
            self.socket.local_addr().unwrap()
        )?;
        if let Some(ipv4) = self.config.loc_tun_in {
            writeln!(f, "{:<15} {}", "ipv4:", ipv4)?;
        }
        if let Some(ipv6) = self.config.loc_tun_in6 {
            writeln!(f, "{:<15} {}", "ipv6:", ipv6)?;
        }

        #[cfg(feature = "holepunch")]
        if let Some(ref rndz) = self.config.rndz {
            writeln!(
                f,
                "{:<15} {}",
                "rndz_server:",
                rndz.server.as_deref().unwrap_or("")
            )?;
            writeln!(
                f,
                "{:<15} {}",
                "rndz_local:",
                rndz.local_id.as_deref().unwrap_or("")
            )?;
            writeln!(
                f,
                "{:<15} {}",
                "rndz_remote:",
                rndz.remote_id.as_deref().unwrap_or("")
            )?;
        }

        writeln!(f, "stats:")?;
        let state = &self.state;
        writeln!(
            f,
            "{:<15} {}",
            "last_ack:",
            state.last_ack.map_or_else(
                || "Never".to_string(),
                |v| format!("{:.0?} ago", v.elapsed())
            )
        )?;
        writeln!(
            f,
            "{:<15} {}",
            "last_rx:",
            state.last_rx.map_or_else(
                || "Never".to_string(),
                |v| format!("{:.0?} ago", v.elapsed())
            )
        )?;
        writeln!(f, "{:<15} {}", "rx:", Size::from_bytes(state.rx_bytes))?;
        writeln!(f, "{:<15} {}", "tx:", Size::from_bytes(state.tx_bytes))?;
        Ok(())
    }
}

impl<'a> poll::Reactor for Client<'a> {
    fn socket_fd(&self) -> RawFd {
        self.socket.as_raw_fd()
    }

    fn tunnel_recv(&mut self) -> Result<()> {
        let mut buf = unsafe { MaybeUninit::assume_init(MaybeUninit::<[u8; 1500]>::uninit()) };
        let size = self.tun.read(&mut buf)?;
        match buf[0] >> 4 {
            4 => self.forward_remote(Kind::V4, &buf[..size])?,
            6 => self.forward_remote(Kind::V6, &buf[..size])?,
            _ => warn!("[INPUT]invalid packet"),
        }

        Ok(())
    }

    fn network_recv(&mut self) -> Result<()> {
        let mut buf = unsafe { MaybeUninit::assume_init(MaybeUninit::<[u8; 1500]>::uninit()) };
        match self.socket.recv_from(&mut buf) {
            Ok((size, src)) => {
                trace!("receive from  {:}, size {:}", src, size);
                match msg::Packet::<&[u8]>::with_cryptor(&mut buf[..size], &self.config.cryptor) {
                    Ok(msg) => match msg.op() {
                        Ok(Op::EchoAck) => {
                            debug!("received echo ack");
                            self.state.last_ack = Some(Instant::now());
                        }
                        Ok(Op::IpData) => {
                            self.state.last_rx = Some(Instant::now());
                            self.forward_local(ipdata::Packet::new(msg.payload()?)?.payload()?)?;
                        }
                        Ok(Op::EchoReq) => {
                            debug!("received echo req(from old version server?)");
                            self.state.last_ack = Some(Instant::now());
                        }
                        _ => debug!("unexpected msg {:?}", msg.op()),
                    },
                    _ => trace!("invalid packet"),
                }
            }
            Err(e) => {
                debug!("recv from server fail. {:?}", e);
            }
        }
        Ok(())
    }

    fn keepalive(&mut self) -> Result<()> {
        let check_timeout = |last_event: Option<Instant>, timeout: &std::time::Duration| -> bool {
            last_event.map_or(true, |event| {
                Instant::now().duration_since(event) > *timeout
            })
        };

        let Config {
            rebind,
            reconnect_timeout,
            rebind_timeout,
            keepalive_interval,
            ..
        } = self.config;

        let State {
            last_rebind,
            last_connect,
            last_ack,
            last_rx,
            last_echo,
            ..
        } = self.state;

        if check_timeout(last_ack, &reconnect_timeout)
            && check_timeout(last_rx, &reconnect_timeout)
            && check_timeout(last_connect, &reconnect_timeout)
        {
            if rebind && check_timeout(last_rebind, &rebind_timeout) {
                info!("Rebind...");
                self.state.last_rebind = Some(Instant::now());
                if let Some(ref factory) = self.config.socket_factory {
                    match factory(&self.config, false) {
                        Ok(socket) => {
                            debug!("rebind to {:}", socket.local_addr()?);
                            self.socket = socket;
                        }
                        Err(e) => warn!("rebind fail, {:}", e),
                    }
                }
            };

            info!("Reconnect...");
            self.state.last_connect = Some(Instant::now());
            if let Some(server_addrs) = &self.config.server_addrs {
                self.server_index = (self.server_index + 1) % server_addrs.len();
                let server_addr = &server_addrs[self.server_index];
                //ignore failure
                let _ = self
                    .socket
                    .connect(build_server_addr(server_addr))
                    .map_err(|e| warn!("{:?}", e));
            }
        }

        if check_timeout(last_echo, &keepalive_interval) {
            self.state.last_echo = Some(Instant::now());
            self.send_echo()?;
        }

        Ok(())
    }

    fn handle_control_connection(&mut self, fd: RawFd) {
        let mut us = unsafe { UnixStream::from_raw_fd(fd) };
        //ignore failure
        let _ = us.write(self.to_string().as_bytes());
    }
}
