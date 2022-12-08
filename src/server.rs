use crate::util::{dest_ip, source_ip};
use crate::{
    config::Config,
    msg,
    msg::{builder::Builder, ipdata, ipdata::Kind, Op},
    poll,
    route::RouteTable,
    state::State,
};
use log::{debug, trace, warn};
use std::error::Error;
use std::io::{Read, Write};
use std::mem::{self, MaybeUninit};
use std::net::{SocketAddr, UdpSocket};
use std::os::unix::io::{AsRawFd, RawFd};
use tun::platform::Device;

type Result = std::result::Result<(), Box<dyn Error>>;

pub struct Server {
    config: Config,
    socket: UdpSocket,
    state: State,
    tun: Device,
    rt: RouteTable,
}

impl Server {
    pub fn new(config: Config, socket: UdpSocket, tun: Device) -> Self {
        Self {
            config,
            socket,
            tun,
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

        poll::poll(self.tun.as_raw_fd(), self)
    }

    fn forward_remote(&mut self, kind: Kind, pkt: &[u8]) -> Result {
        let dst = dest_ip(pkt)?;
        let va = match self.rt.get_route(&dst) {
            Some(va) => va,
            None => Err(crate::error::Error::NoRoute(dst.to_string()))?,
        };

        let buf = msg::Builder::default()
            .cryptor(&self.config.cryptor)?
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
                debug!("unknown src {:}", src);
                return Ok(());
            }
        }

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
            .cryptor(&self.config.cryptor)?
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
    fn socket_fd(&self) -> RawFd {
        self.socket.as_raw_fd()
    }
    fn tunnel_recv(&mut self) -> Result {
        let mut buf =
            unsafe { mem::MaybeUninit::assume_init(mem::MaybeUninit::<[u8; 1500]>::uninit()) };
        let size = self.tun.read(&mut buf)?;
        match buf[0] >> 4 {
            4 => {
                let _ = self
                    .forward_remote(Kind::V4, &buf[..size])
                    .map_err(|e| debug!("forward remote fail. {:?}", e));
            }
            6 => {
                let _ = self
                    .forward_remote(Kind::V6, &buf[..size])
                    .map_err(|e| debug!("forward remote fail. {:?}", e));
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
                debug!("receive from client fail. {:?}", e);
                return Ok(());
            }
        };

        trace!("receive from  {:}, size {:}", src, size);
        match msg::Packet::<&[u8]>::with_cryptor(&mut buf[..size], &self.config.cryptor) {
            Ok(msg) => match msg.op() {
                Ok(Op::IpData) => {
                    self.forward_local(&src, ipdata::Packet::new(msg.payload()?)?.payload()?)?;
                }
                Ok(Op::EchoReq) => {
                    let echo = msg::echo::Packet::new(msg.payload()?)?;
                    debug!("received echo req {:?}", echo.ip_addr()?);
                    self.handle_echo_req(src, echo)?;
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
        self.rt.prune();
        Ok(())
    }
}
