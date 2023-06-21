use crate::config::Config;
use crate::msg;
use crate::poll;
use crate::{
    error::Error,
    msg::Op,
    msg::{builder::Builder, ipdata, ipdata::Kind},
    socket::Socket,
    state::State,
};
use log::{debug, info, trace, warn};
use size::Size;
use std::fmt::{Display, Formatter};
use std::io::{Read, Write};
use std::mem::MaybeUninit;
use std::os::unix::io::FromRawFd;
use std::os::unix::io::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::time::Instant;
use tun::platform::posix::Fd;

extern crate libc;

type Result = std::result::Result<(), Box<dyn std::error::Error>>;

pub struct Client<'a> {
    config: Config<'a>,
    socket: Socket,
    state: State,
    tun: Fd,
    last_rebind: Option<Instant>,
}

impl<'a> Client<'a> {
    pub fn new(mut config: Config<'a>) -> std::result::Result<Self, Error> {
        let socket = match config.socket.take() {
            Some(socket) => socket,
            None => config
                .socket_factory
                .as_ref()
                .expect("neither socket nor socket_factory is set")(
                &config, config.wait_dns
            )?,
        };
        let tun = Fd::new(config.tun_fd).unwrap();
        Ok(Self {
            config,
            socket,
            tun,
            state: Default::default(),
            last_rebind: None,
        })
    }

    pub fn run(mut self) -> Result {
        if let Some(ref server_addr) = self.config.server_addr {
            let _ = self.socket.connect(server_addr);
        }
        self.state.last_connect = Some(Instant::now());

        poll::poll(self.tun.as_raw_fd(), self.config.control_fd, self)
    }

    fn forward_remote(&mut self, kind: Kind, pkt: &[u8]) -> Result {
        self.state.tx_bytes += pkt.len() as u64;

        let buf = msg::Builder::default()
            .cryptor(&self.config.cryptor)?
            .seq(self.state.next_seq())?
            .ip_data()?
            .kind(kind)?
            .payload(pkt)?
            .build()?;

        let _ = self.socket.send(&buf);
        Ok(())
    }

    fn forward_local(&mut self, pkt: &[u8]) -> Result {
        self.state.rx_bytes += pkt.len() as u64;

        match pkt[0] >> 4 {
            4 | 6 => {
                let _ = self.tun.write(pkt)?;
            }
            _ => {
                debug!("[FWD]invalid packet!")
            }
        }

        Ok(())
    }

    fn send_echo(&mut self) -> Result {
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

        let _ = self.socket.send(builder.build()?.as_ref());

        Ok(())
    }
}

impl<'a> Display for Client<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        writeln!(f, "client mode")?;
        writeln!(
            f,
            "{:<15} {:}",
            "server_addr:",
            self.config
                .server_addr
                .clone()
                .or(self.socket.peer_addr().map(|v| v.to_string()).ok())
                .unwrap_or("NA".to_string())
        )?;
        writeln!(
            f,
            "{:<15} {:}",
            "local_addr:",
            self.socket.local_addr().unwrap()
        )?;
        if let Some(ipv4) = self.config.loc_tun_in {
            writeln!(f, "{:<15} {:}", "ipv4:", ipv4)?;
        }
        if let Some(ipv6) = self.config.loc_tun_in6 {
            writeln!(f, "{:<15} {:}", "ipv6:", ipv6)?;
        }

        #[cfg(feature = "holepunch")]
        if let Some(ref rndz) = self.config.rndz {
            writeln!(
                f,
                "{:<15} {:}",
                "rndz_server:",
                rndz.server.as_ref().unwrap_or(&"".to_owned())
            )?;
            writeln!(
                f,
                "{:<15} {:}",
                "rndz_local:",
                rndz.local_id.as_ref().unwrap_or(&"".to_owned())
            )?;
            writeln!(
                f,
                "{:<15} {:}",
                "rndz_remote:",
                rndz.remote_id.as_ref().unwrap_or(&"".to_owned())
            )?;
        }

        writeln!(f, "stats:")?;

        let state = &self.state;
        writeln!(
            f,
            "{:<15} {:}",
            "last_ack:",
            state
                .last_ack
                .map_or("Never".to_string(), |v| format!("{:.0?} ago", v.elapsed()))
        )?;
        writeln!(
            f,
            "{:<15} {:}",
            "rx:",
            Size::from_bytes(state.rx_bytes).to_string()
        )?;
        writeln!(
            f,
            "{:<15} {:}",
            "tx:",
            Size::from_bytes(state.tx_bytes).to_string()
        )?;
        Ok(())
    }
}

impl<'a> poll::Reactor for Client<'a> {
    fn socket_fd(&self) -> RawFd {
        self.socket.as_raw_fd()
    }

    fn tunnel_recv(&mut self) -> Result {
        let mut buf = unsafe { MaybeUninit::assume_init(MaybeUninit::<[u8; 1500]>::uninit()) };
        let size = self.tun.read(&mut buf)?;
        match buf[0] >> 4 {
            4 => {
                self.forward_remote(Kind::V4, &buf[..size])?;
            }
            6 => {
                self.forward_remote(Kind::V6, &buf[..size])?;
            }
            _ => {
                warn!("[INPUT]invalid packet");
            }
        }

        Ok(())
    }

    fn network_recv(&mut self) -> Result {
        let mut buf = unsafe { MaybeUninit::assume_init(MaybeUninit::<[u8; 1500]>::uninit()) };
        let (size, src) = match self.socket.recv_from(&mut buf) {
            Ok((size, src)) => (size, src),
            Err(e) => {
                debug!("recv from server fail. {:?}", e);
                return Ok(());
            }
        };
        trace!("receive from  {:}, size {:}", src, size);
        match msg::Packet::<&[u8]>::with_cryptor(&mut buf[..size], &self.config.cryptor) {
            Ok(msg) => match msg.op() {
                Ok(Op::EchoAck) => {
                    debug!("received echo ack");
                    self.state.last_ack = Some(Instant::now());
                }
                Ok(Op::IpData) => {
                    self.forward_local(ipdata::Packet::new(msg.payload()?)?.payload()?)?;
                }
                Ok(Op::EchoReq) => {
                    debug!("received echo req(from old version server?)");
                    self.state.last_ack = Some(Instant::now());
                }
                _ => {
                    debug!("unexpected msg {:?}", msg.op());
                }
            },
            _ => {
                trace!("invalid packet")
            }
        }

        Ok(())
    }

    fn keepalive(&mut self) -> Result {
        if !self.config.reconnect_timeout.is_zero() {
            let ack_timeout = self.state.last_ack.map_or(true, |last_ack| {
                Instant::now().duration_since(last_ack) > self.config.reconnect_timeout
            });

            if ack_timeout {
                let reconnect = self.state.last_connect.map_or(true, |last_connect| {
                    Instant::now().duration_since(last_connect) > self.config.reconnect_timeout
                });

                if reconnect {
                    if self.config.rebind
                        && self
                            .last_rebind
                            .map(|l| l.elapsed() > self.config.rebind_timeout)
                            .unwrap_or(true)
                    {
                        info!("Rebind...");
                        self.last_rebind = Some(Instant::now());
                        if let Some(ref factory) = self.config.socket_factory {
                            match factory(&self.config, false) {
                                Ok(socket) => {
                                    debug!("rebind to {:}", socket.local_addr().unwrap());
                                    self.socket = socket
                                }
                                Err(e) => warn!("rebind fail, {:}", e),
                            }
                        }
                    } else {
                        info!("Reconnect...");
                    }

                    self.state.last_connect = Some(Instant::now());
                    if let Some(ref server_addr) = self.config.server_addr {
                        let _ = self
                            .socket
                            .connect(server_addr)
                            .map_err(|e| warn!("{:?}", e));
                    }
                }
            };
        }

        if !self.config.keepalive_interval.is_zero() {
            match self.state.last_echo {
                Some(last_echo)
                    if Instant::now().duration_since(last_echo)
                        < self.config.keepalive_interval => {}
                _ => {
                    self.state.last_echo = Some(Instant::now());
                    self.send_echo()?;
                }
            }
        }

        Ok(())
    }

    fn handle_control_connection(&mut self, fd: RawFd) {
        let mut us = unsafe { UnixStream::from_raw_fd(fd) };
        let _ = us.write(self.to_string().as_bytes());
    }
}
