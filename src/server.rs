use crate::socket::{AsUdpSocket, Socket};
use crate::util::{dest_ip, source_ip};
use crate::{
    config::Config, msg, msg::builder::Builder, msg::ipdata, poll, route::RouteTable, state::State,
};
use std::error::Error;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::os::unix::io::AsRawFd;
use tun::platform::Device;

type Result = std::result::Result<(), Box<dyn Error>>;

pub struct Server {
    config: Config,
    socket: Box<dyn AsUdpSocket>,
    state: State,
    tun: Device,
    rt: RouteTable,
}

impl Server {
    pub fn new(config: Config, socket: Box<dyn AsUdpSocket>, tun: Device) -> Self {
        Self {
            config: config,
            socket: socket,
            tun: tun,
            state: Default::default(),
            rt: Default::default(),
        }
    }

    pub fn run(mut self) -> Result {
        for (net, gw) in &self.config.routes {
            match gw {
                Some(gw) => self.rt.add_route(net, gw),
                None => Err("route gw must be set in server mode!")?,
            }
        }

        self.socket.listen()?;

        poll::poll(self.tun.as_raw_fd(), self.socket.as_raw_fd(), self)
    }

    fn forward_remote(&mut self, kind: ipdata::Kind, pkt: &[u8]) -> Result {
        let dst = dest_ip(pkt)?;
        let va = match self.rt.get_route(&dst) {
            Some(va) => va,
            None => Err(crate::error::Error::NoRoute(dst.to_string()))?,
        };

        let buf = msg::Builder::default()
            .cryptor(self.config.cryptor.build())?
            .seq(va.ra.next_seq())?
            .ip_data()?
            .kind(kind)?
            .payload(pkt)?
            .build()?;

        let _ = self.socket.send_to(&buf, va.ra.addr());
        Ok(())
    }

    fn forward_local(&mut self, ra: &SocketAddr, pkt: &[u8]) -> Result {
        let src = source_ip(pkt)?;
        match self.rt.get_and_update_route(&src, ra) {
            Some(_) => {}
            None => {
                log::debug!("unknown src {:}", src);
                return Ok(());
            }
        }

        match pkt.as_ref()[0] >> 4 {
            4 | 6 => {
                self.tun.write(pkt)?;
            }
            _ => {
                log::debug!("[FWD]invalid packet!")
            }
        }

        Ok(())
    }

    fn handle_echo_req<T: AsRef<[u8]>>(
        &mut self,
        src: SocketAddr,
        pkt: msg::echo::Packet<T>,
    ) -> Result {
        let ra = self.rt.get_or_add_ra(&src);

        let (va4, va6) = pkt.ip_addr()?;
        if !va4.is_unspecified() {
            self.rt.add_or_update_va(&va4.into(), &ra);
        }
        if !va6.is_unspecified() {
            self.rt.add_or_update_va(&va6.into(), &ra);
        }

        let mut builder = msg::Builder::default()
            .cryptor(self.config.cryptor.build())?
            .seq(ra.next_seq())?
            .echo_ack()?
            .id(pkt.id()?)?;

        if let Some(ref addr4) = self.config.loc_tun_in {
            builder = builder.ipv4_addr(addr4.addr())?;
        }

        if let Some(ref addr6) = self.config.loc_tun_in6 {
            builder = builder.ipv6_addr(addr6.addr())?;
        }

        let buf = builder.build()?;

        let _ = self.socket.send_to(&buf, src);

        Ok(())
    }
}

impl poll::Reactor for Server {
    fn tunnel_recv(&mut self) -> Result {
        let mut buf = [0; 1600];
        let size = self.tun.read(&mut buf)?;
        match buf[0] >> 4 {
            4 => {
                let _ = self
                    .forward_remote(ipdata::Kind::V4, &buf[..size])
                    .map_err(|e| log::debug!("forward remote fail. {:?}", e));
            }
            6 => {
                let _ = self
                    .forward_remote(ipdata::Kind::V6, &buf[..size])
                    .map_err(|e| log::debug!("forward remote fail. {:?}", e));
            }
            _ => {
                log::warn!("[INPUT]invalid packet");
            }
        }

        Ok(())
    }

    fn network_recv(&mut self) -> Result {
        let mut buf = [0; 1600];
        let (size, src) = match self.socket.recv_from(&mut buf) {
            Ok((size, src)) => (size, src),
            Err(e) => {
                log::debug!("receive from client fail. {:?}", e);
                return Ok(());
            }
        };
        log::trace!("receive from  {:}, size {:}", src, size);
        match msg::Packet::with_cryptor(&buf[..size], self.config.cryptor.build()) {
            Ok(msg) => match msg.op() {
                Ok(msg::Op::IpData) => {
                    self.forward_local(&src, ipdata::Packet::new(msg.payload()?)?.payload()?)?;
                }
                Ok(msg::Op::EchoReq) => {
                    let echo = msg::echo::Packet::new(msg.payload()?)?;
                    log::debug!("received echo req {:?}", echo.ip_addr()?);
                    self.handle_echo_req(src, echo)?;
                }
                _ => {
                    log::debug!("unexpected msg {:?}", msg.op());
                }
            },
            _ => {
                log::trace!("invalid packet")
            }
        }

        Ok(())
    }

    fn keepalive(&mut self) -> Result {
        self.rt.prune();
        Ok(())
    }
}
