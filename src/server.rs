use crate::util::{dest_ip, source_ip};
use crate::{
    config::Config,
    error::Error,
    msg,
    msg::{builder::Builder, ipdata, ipdata::Kind, Op},
    poll,
    route::RouteTable,
    socket::Socket,
};
use log::{debug, info, trace, warn};
use pretty_duration::pretty_duration;
use size::Size;
use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use std::io::{Read, Write};
use std::mem::{self, MaybeUninit};
use std::net::{IpAddr, SocketAddr};
use std::os::unix::io::FromRawFd;
use std::os::unix::io::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::time::Instant;
use tun::platform::posix::Fd;

type Result = std::result::Result<(), Box<dyn std::error::Error>>;

#[derive(Default)]
pub struct Stat {
    rx_bytes: u64,
    tx_bytes: u64,
}

pub struct Server<'a> {
    config: Config<'a>,
    socket: Socket,
    stats: HashMap<IpAddr, Stat>,
    tun: Fd,
    rt: RouteTable,
    last_rebind: Option<Instant>,
}

impl<'a> Server<'a> {
    pub fn new(mut config: Config<'a>) -> std::result::Result<Self, Error> {
        let socket = match config.socket.take() {
            Some(socket) => socket,
            None => config
                .socket_factory
                .as_ref()
                .expect("neither socket nor socket_factory is set")(&config)?,
        };
        let tun = Fd::new(config.tun_fd).unwrap();
        Ok(Self {
            config,
            socket,
            tun,
            stats: Default::default(),
            rt: Default::default(),
            last_rebind: None,
        })
    }

    pub fn run(mut self) -> Result {
        for (net, gw) in &self.config.routes {
            match gw {
                Some(gw) => self.rt.add_route(net, gw),
                None => Err("route gw must be set in server mode!")?,
            }
        }

        poll::poll(self.tun.as_raw_fd(), self.config.control_fd, self)
    }

    fn forward_remote(&mut self, kind: Kind, pkt: &[u8]) -> Result {
        let dst = dest_ip(pkt)?;
        let va = match self.rt.get_route(&dst) {
            Some(va) => va,
            None => Err(crate::error::Error::NoRoute(dst.to_string()))?,
        };

        let mut stat = self.stats.entry(dst).or_default();
        stat.tx_bytes += pkt.len() as u64;

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
        if !self.rt.update_va(&src, ra) {
            debug!("unknown src {:}", src);
            return Ok(());
        }

        let mut stat = self.stats.entry(src).or_default();
        stat.rx_bytes += pkt.len() as u64;

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
        let ra = self.rt.get_or_add_ra(&src).clone();

        let (va4, va6) = pkt.ip_addr()?;
        if !va4.is_unspecified() {
            self.rt.add_or_update_va(&va4.into(), ra.clone());
        }
        if !va6.is_unspecified() {
            self.rt.add_or_update_va(&va6.into(), ra.clone());
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
impl<'a> Display for Server<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        writeln!(f, "server mode")?;
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
                "rndz_id:",
                rndz.local_id.as_ref().unwrap_or(&"".to_owned())
            )?;
            writeln!(
                f,
                "{:<15} {:}",
                "rndz_health:",
                self.socket
                    .last_health()
                    .map(|v| format!("{:.0?} ago", pretty_duration(&v.elapsed(), None)))
                    .unwrap_or("Never".to_owned())
            )?;
        }

        write!(f, "{:}", self.rt)?;

        writeln!(f, "stats:")?;
        let mut stat = self.stats.iter().collect::<Vec<_>>();
        stat.sort_by(|a, b| a.0.partial_cmp(b.0).unwrap());
        for s in stat {
            writeln!(
                f,
                "{:<15} rx: {:>10}\t tx: {:>10}",
                s.0,
                Size::from_bytes(s.1.rx_bytes).to_string(),
                Size::from_bytes(s.1.tx_bytes).to_string(),
            )?;
        }

        Ok(())
    }
}

impl<'a> poll::Reactor for Server<'a> {
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
        let Config {
            rebind,
            reconnect_timeout,
            socket_factory,
            ..
        } = self.config;

        if rebind
            && self.socket.is_stale()
            && self
                .last_rebind
                .map(|l| l.elapsed() > reconnect_timeout)
                .unwrap_or(true)
        {
            info!("Rebind...");

            self.last_rebind = Some(Instant::now());
            if let Some(factory) = socket_factory {
                match factory(&self.config) {
                    Ok(socket) => {
                        debug!("rebind to {:}", socket.local_addr().unwrap());
                        self.socket = socket;
                    }
                    Err(e) => {
                        warn!("rebind fail.{:} ", e);
                    }
                }
            }
        }

        let Self { rt, stats, .. } = self;

        rt.prune(self.config.client_timeout);
        stats.retain(|k, _| rt.contains(k));
        Ok(())
    }

    fn handle_control_connection(&mut self, fd: RawFd) {
        let mut us = unsafe { UnixStream::from_raw_fd(fd) };
        let _ = us.write(self.to_string().as_bytes());
    }
}
