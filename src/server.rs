use crate::msg::{EchoPacket, IpDataPacket};
use crate::util::{dest_ip, source_ip};
use crate::{
    config::Config,
    error::Error,
    msg::{Builder, IpDataKind, MsgBuilder, MsgPacket, Op},
    poll,
    route::{RefRA, RouteTable},
    socket::Socket,
    Runtime,
};
use log::{debug, info, trace, warn};
use nix::unistd::{read, write};
use size::Size;
use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use std::io::Write;
use std::mem::{self, MaybeUninit};
use std::net::{IpAddr, SocketAddr};
use std::os::fd::OwnedFd;
use std::os::unix::io::FromRawFd;
use std::os::unix::io::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::rc::Rc;
use std::time::Instant;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Default)]
pub struct Stat {
    rx_bytes: u64,
    tx_bytes: u64,
}

pub struct Server {
    config: Rc<Config>,
    rt: Runtime,
    stats: RefCell<HashMap<IpAddr, Stat>>,
    route: RefCell<RouteTable>,
    last_rebind: Option<Instant>,
    last_health: Option<Instant>,
}

impl Server {
    pub fn new(config: Rc<Config>, rt: Runtime) -> std::result::Result<Self, Error> {
        Ok(Self {
            config,
            rt,
            stats: Default::default(),
            route: Default::default(),
            last_rebind: Some(Instant::now()),
            last_health: None,
        })
    }

    pub fn run(self) -> Result<()> {
        for (net, gw) in &self.config.routes {
            match gw {
                Some(gw) => self.route.borrow_mut().add_route(net, gw),
                None => return Err("route gw must be set in server mode!".into()),
            }
        }

        poll::poll(
            self.tun().as_raw_fd(),
            self.rt.control_fd.as_ref().map(|v| v.as_raw_fd()),
            self.rt.exit_signal.as_ref().map(|v| v.as_raw_fd()),
            self,
        )
    }

    fn socket(&self) -> Option<&Socket> {
        self.rt.socket.as_deref()
    }

    fn tun(&self) -> &OwnedFd {
        &self.rt.tun_fd
    }

    fn forward_remote(&self, kind: IpDataKind, pkt: &[u8]) -> Result<()> {
        let dst = dest_ip(pkt)?;
        let mut route = self.route.borrow_mut();
        let va = route
            .get_route(&dst)
            .ok_or_else(|| crate::error::Error::NoRoute(dst.to_string()))?;

        let mut stats = self.stats.borrow_mut();
        let stat = stats.entry(dst).or_default();
        stat.tx_bytes += pkt.len() as u64;

        let msg = self.new_msg(&va.ra)?.ip_data()?.kind(kind)?.payload(pkt)?;

        let dst = va.ra.addr();

        if let Some(s) = self.socket() {
            // ignore failure
            let _ = s.send_to(&msg.build()?, dst);
        }

        Ok(())
    }

    fn forward_local(&self, ra: &SocketAddr, pkt: &[u8]) -> Result<()> {
        let src = source_ip(pkt)?;
        let ra = self.route.borrow_mut().get_or_add_ra(ra).clone();
        if self.route.borrow_mut().add_or_update_va(&src, ra).is_none() {
            debug!("unknown src {:}", src);
            return Ok(());
        }
        let mut stats = self.stats.borrow_mut();
        let stat = stats.entry(src).or_default();
        stat.rx_bytes += pkt.len() as u64;

        match pkt[0] >> 4 {
            4 | 6 => {
                // ignore failure
                let _ = write(self.tun(), pkt)?;
            }
            _ => {
                debug!("[FWD] invalid packet!")
            }
        }

        Ok(())
    }

    fn handle_echo_req<T: AsRef<[u8]>>(&self, src: SocketAddr, pkt: EchoPacket<T>) -> Result<()> {
        let ra = self.route.borrow_mut().get_or_add_ra(&src).clone();

        let (va4, va6) = pkt.ip_addr()?;
        if !va4.is_unspecified() {
            self.route
                .borrow_mut()
                .add_or_update_va(&va4.into(), ra.clone());
        }
        if !va6.is_unspecified() {
            self.route
                .borrow_mut()
                .add_or_update_va(&va6.into(), ra.clone());
        }

        let mut msg = self.new_msg(&ra)?.echo_ack()?.id(pkt.id()?)?;

        if let Some(ref addr4) = self.config.loc_tun_in {
            msg = msg.ipv4_addr(addr4.addr())?;
        }

        if let Some(ref addr6) = self.config.loc_tun_in6 {
            msg = msg.ipv6_addr(addr6.addr())?;
        }

        if let Some(s) = self.socket() {
            // ignore failure
            let _ = s.send_to(&msg.build()?, src);
        }

        Ok(())
    }

    fn new_msg(&self, ra: &RefRA) -> Result<MsgBuilder> {
        let builder = MsgBuilder::default()
            .with_cryptor(self.config.cryptor())?
            .seq(ra.next_seq())?;

        Ok(builder)
    }
}

impl Display for Server {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        writeln!(f, "server mode")?;
        writeln!(
            f,
            "{:<15} {:}",
            "local_addr:",
            self.socket()
                .ok_or(std::io::Error::other("socket not created"))
                .and_then(|s| s.local_addr())
                .map(|v| v.to_string())
                .unwrap_or_else(|_| "NA".to_string())
        )?;
        if let Some(ipv4) = self.config.loc_tun_in {
            writeln!(f, "{:<15} {:}", "ipv4:", ipv4)?;
        }
        if let Some(ipv6) = self.config.loc_tun_in6 {
            writeln!(f, "{:<15} {:}", "ipv6:", ipv6)?;
        }

        #[cfg(feature = "holepunch")]
        if let Some(ref rndz) = self.config.rndz {
            writeln!(f, "{:<15} {:}", "rndz_server:", rndz.server)?;
            writeln!(f, "{:<15} {:}", "rndz_id:", rndz.local_id)?;
            writeln!(
                f,
                "{:<15} {:}",
                "rndz_health:",
                self.socket()
                    .ok_or(std::io::Error::other("socket not created"))
                    .map(|s| s.last_health())
                    .unwrap_or(self.last_health)
                    .map(|v| format!("{} ago", crate::util::pretty_duration(&v.elapsed())))
                    .unwrap_or_else(|| "Never".to_owned())
            )?;
        }

        write!(f, "{:}", self.route.borrow())?;

        writeln!(f, "stats:")?;
        let stats = self.stats.borrow();
        let mut stat = stats.iter().collect::<Vec<_>>();
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

impl poll::Reactor for Server {
    fn socket_fd(&self) -> Option<RawFd> {
        self.socket().map(|s| s.as_raw_fd())
    }

    fn tunnel_recv(&self) -> Result<()> {
        let mut buf =
            unsafe { mem::MaybeUninit::assume_init(mem::MaybeUninit::<[u8; 1500]>::uninit()) };
        let size = read(self.tun().as_raw_fd(), &mut buf)?;
        match buf[0] >> 4 {
            4 => {
                // ignore failure
                let _ = self
                    .forward_remote(IpDataKind::V4, &buf[..size])
                    .map_err(|e| debug!("forward remote fail. {:?}", e));
            }
            6 => {
                // ignore failure
                let _ = self
                    .forward_remote(IpDataKind::V6, &buf[..size])
                    .map_err(|e| debug!("forward remote fail. {:?}", e));
            }
            _ => {
                warn!("[INPUT] invalid packet");
            }
        }

        Ok(())
    }

    fn network_recv(&self) -> Result<()> {
        let s = match self.socket() {
            Some(s) => s,
            None => return Ok(()),
        };

        let mut buf = unsafe { MaybeUninit::assume_init(MaybeUninit::<[u8; 1500]>::uninit()) };
        let (size, src) = match s.recv_from(&mut buf) {
            Ok((size, src)) => (size, src),
            Err(e) => {
                debug!("receive from client fail. {:?}", e);
                return Ok(());
            }
        };

        trace!("receive from {:}, size {:}", src, size);
        match MsgPacket::<&[u8]>::with_cryptor(&mut buf[..size], self.config.cryptor()) {
            Ok(msg) => match msg.op() {
                Ok(Op::IpData) => {
                    self.forward_local(&src, IpDataPacket::new(msg.payload()?)?.payload()?)?;
                }
                Ok(Op::EchoReq) => {
                    let echo = EchoPacket::new(msg.payload()?)?;
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

    fn keepalive(&mut self) -> Result<()> {
        let Config {
            rebind,
            rebind_timeout,
            ..
        } = *self.config;

        if rebind
            && (self.socket().map(|s| s.is_stale()).unwrap_or(true)
                || self
                    .last_health
                    .map(|l| l.elapsed() > rebind_timeout)
                    .unwrap_or(true))
            && self
                .last_rebind
                .map(|l| l.elapsed() > rebind_timeout)
                .unwrap_or(true)
        {
            info!("Rebind...");

            self.last_rebind = Some(Instant::now());
            if let Some(ref factory) = self.rt.socket_factory {
                match factory.create_socket() {
                    Ok(socket) => {
                        debug!("rebind to {:}", socket.local_addr().unwrap());
                        self.rt.with_socket(socket);
                    }
                    Err(e) => {
                        warn!("rebind fail. {:}", e);
                    }
                }
            }
        }

        if let Some(last_health) = self.socket().and_then(|s| s.last_health()) {
            self.last_health = Some(last_health);
        }

        let Self { route, stats, .. } = self;

        route.get_mut().prune(self.config.client_timeout);
        stats.get_mut().retain(|k, _| route.borrow().contains(k));
        Ok(())
    }

    fn handle_control_connection(&self, fd: RawFd) {
        let mut us = unsafe { UnixStream::from_raw_fd(fd) };
        // ignore failure
        let _ = us.write(self.to_string().as_bytes());
    }
}
