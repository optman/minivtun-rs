use crate::config::Config;
use crate::msg;
use crate::poll;
use crate::{
    msg::Op,
    msg::{builder::Builder, ipdata, ipdata::Kind},
    state::State,
};
use log::{debug, info, trace, warn};
use std::error::Error;
use std::io::{Read, Write};

use std::mem::MaybeUninit;
use std::net::UdpSocket;
use std::os::unix::io::{AsRawFd, RawFd};
use std::time::Instant;
use tun::platform::posix::Fd;

extern crate libc;

type Result = std::result::Result<(), Box<dyn Error>>;

pub struct Client<'a> {
    config: Config<'a>,
    socket: UdpSocket,
    state: State,
    tun: Fd,
}

impl<'a> Client<'a> {
    pub fn new(mut config: Config<'a>) -> Self {
        let socket = config
            .socket
            .take()
            .unwrap_or_else(|| config.socket_factory.as_ref().unwrap()(&config));
        let tun = Fd::new(config.tun_fd).unwrap();
        Self {
            config,
            socket,
            tun,
            state: Default::default(),
        }
    }

    pub fn run(mut self) -> Result {
        let _ = self.socket.connect(
            self.config
                .server_addr
                .as_ref()
                .ok_or("server_addr not set")?,
        );
        self.state.last_connect = Some(Instant::now());

        poll::poll(self.tun.as_raw_fd(), self)
    }

    fn forward_remote(&mut self, kind: Kind, pkt: &[u8]) -> Result {
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
        let ack_timeout = self.state.last_ack.map_or(true, |last_ack| {
            Instant::now().duration_since(last_ack) > self.config.reconnect_timeout
        });

        if ack_timeout {
            let reconnect = self.state.last_connect.map_or(true, |last_connect| {
                Instant::now().duration_since(last_connect) > self.config.reconnect_timeout
            });

            if reconnect {
                info!("Reconnect...");

                if self.config.rebind && self.config.socket_factory.is_some() {
                    self.socket = self.config.socket_factory.unwrap()(&self.config);
                    debug!("rebind to {:}", self.socket.local_addr().unwrap());
                }

                self.state.last_connect = Some(Instant::now());
                let _ = self
                    .socket
                    .connect(self.config.server_addr.as_ref().unwrap())
                    .map_err(|e| debug!("{:?}", e));
            }
        };

        match self.state.last_echo {
            Some(last_echo)
                if Instant::now().duration_since(last_echo) < self.config.keepalive_interval => {}
            _ => {
                self.state.last_echo = Some(Instant::now());
                self.send_echo()?;
            }
        }

        Ok(())
    }
}
