use crate::config::Config;
use crate::msg;
use crate::poll;
use crate::Runtime;
use crate::{
    msg::Op,
    msg::{builder::Builder, ipdata, ipdata::Kind},
    state::State,
    util::build_server_addr,
    util::pretty_duration,
    Socket,
};
use log::{debug, info, trace, warn};
use nix::unistd::{read, write};
use size::Size;
use std::cell::RefCell;
use std::fmt::Formatter;
use std::io::Write;
use std::mem::MaybeUninit;
use std::os::fd::OwnedFd;
use std::os::unix::io::FromRawFd;
use std::os::unix::io::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::rc::Rc;
use std::time::Instant;

extern crate libc;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub struct Client {
    pub(crate) config: Rc<Config>,
    pub(crate) rt: Runtime,
    pub(crate) state: RefCell<State>,
    pub(crate) server_index: usize,
}

impl Client {
    pub fn new(config: Rc<Config>, rt: Runtime) -> Result<Self> {
        Ok(Self {
            config,
            rt,
            state: Default::default(),
            server_index: 0,
        })
    }

    pub fn run(self) -> Result<()> {
        if let Some(server_addr) = self
            .config
            .server_addrs
            .as_ref()
            .and_then(|addrs| addrs.get(self.server_index))
        {
            if let Some(s) = self.socket() {
                //ignore failure
                let _ = s
                    .connect(&build_server_addr(server_addr))
                    .inspect_err(|e| warn!("{:?}", e));
            }
        }
        self.state.borrow_mut().last_connect = Some(Instant::now());

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

    fn forward_remote(&self, kind: Kind, pkt: &[u8]) -> Result<()> {
        self.state.borrow_mut().tx_bytes += pkt.len() as u64;

        let buf = self
            .new_msg()?
            .ip_data()?
            .kind(kind)?
            .payload(pkt)?
            .build()?;

        if let Some(s) = self.socket() {
            //ignore failure
            let _ = s.send(&buf);
        }

        Ok(())
    }

    fn forward_local(&self, pkt: &[u8]) -> Result<()> {
        self.state.borrow_mut().rx_bytes += pkt.len() as u64;

        match pkt[0] >> 4 {
            4 | 6 => {
                //ignore failure
                let _ = write(self.tun(), pkt);
            }
            _ => debug!("[FWD]invalid packet!"),
        }

        Ok(())
    }

    fn send_echo(&self) -> Result<()> {
        let mut builder = self
            .new_msg()?
            .echo_req()?
            .id(self.state.borrow().gen_id())?;

        if let Some(ref addr4) = self.config.loc_tun_in {
            builder = builder.ipv4_addr(addr4.addr())?;
        }

        if let Some(ref addr6) = self.config.loc_tun_in6 {
            builder = builder.ipv6_addr(addr6.addr())?;
        }

        if let Some(s) = self.socket() {
            //ignore failure
            let _ = s.send(builder.build()?.as_ref());
        }

        Ok(())
    }

    fn new_msg(&self) -> Result<msg::Builder> {
        let builder = msg::Builder::default()
            .cryptor(&self.config.cryptor)?
            .seq(self.state.borrow_mut().next_seq())?;

        Ok(builder)
    }
}

impl std::fmt::Display for Client {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        writeln!(f, "client mode")?;
        writeln!(
            f,
            "{:<15} {}",
            "server_addr:",
            self.socket()
                .ok_or(std::io::Error::other("socket not created"))
                .and_then(|s| s.peer_addr())
                .map(|v| v.to_string())
                .unwrap_or_else(|_| "NA".to_string())
        )?;
        writeln!(
            f,
            "{:<15} {}",
            "local_addr:",
            self.socket()
                .ok_or(std::io::Error::other("socket not created"))
                .and_then(|s| s.local_addr())
                .map(|v| v.to_string())
                .unwrap_or_else(|_| "NA".to_string())
        )?;
        if let Some(ipv4) = self.config.loc_tun_in {
            writeln!(f, "{:<15} {}", "ipv4:", ipv4)?;
        }
        if let Some(ipv6) = self.config.loc_tun_in6 {
            writeln!(f, "{:<15} {}", "ipv6:", ipv6)?;
        }

        #[cfg(feature = "holepunch")]
        if let Some(ref rndz) = self.config.rndz {
            writeln!(f, "{:<15} {}", "rndz_server:", rndz.server)?;
            writeln!(f, "{:<15} {}", "rndz_local:", rndz.local_id)?;
            writeln!(
                f,
                "{:<15} {}",
                "rndz_remote:",
                rndz.remote_id.as_deref().unwrap_or("")
            )?;
        }

        writeln!(f, "stats:")?;
        let state = self.state.borrow();
        writeln!(
            f,
            "{:<15} {}",
            "last_ack:",
            state.last_ack.map_or_else(
                || "Never".to_string(),
                |v| format!("{} ago", pretty_duration(&v.elapsed()))
            )
        )?;
        writeln!(
            f,
            "{:<15} {}",
            "last_rx:",
            state.last_rx.map_or_else(
                || "Never".to_string(),
                |v| format!("{} ago", pretty_duration(&v.elapsed()))
            )
        )?;
        writeln!(f, "{:<15} {}", "rx:", Size::from_bytes(state.rx_bytes))?;
        writeln!(f, "{:<15} {}", "tx:", Size::from_bytes(state.tx_bytes))?;
        Ok(())
    }
}

impl poll::Reactor for Client {
    fn socket_fd(&self) -> Option<RawFd> {
        self.socket().map(|s| s.as_raw_fd())
    }

    fn tunnel_recv(&self) -> Result<()> {
        let mut buf = unsafe { MaybeUninit::assume_init(MaybeUninit::<[u8; 1500]>::uninit()) };
        let size = read(self.tun().as_raw_fd(), &mut buf)?;
        match buf[0] >> 4 {
            4 => self.forward_remote(Kind::V4, &buf[..size])?,
            6 => self.forward_remote(Kind::V6, &buf[..size])?,
            _ => warn!("[INPUT]invalid packet"),
        }

        Ok(())
    }

    fn network_recv(&self) -> Result<()> {
        let s = match self.socket() {
            Some(s) => s,
            None => return Ok(()),
        };

        let mut buf = unsafe { MaybeUninit::assume_init(MaybeUninit::<[u8; 1500]>::uninit()) };
        match s.recv_from(&mut buf) {
            Ok((size, src)) => {
                trace!("receive from  {:}, size {:}", src, size);
                match msg::Packet::<&[u8]>::with_cryptor(&mut buf[..size], &self.config.cryptor) {
                    Ok(msg) => match msg.op() {
                        Ok(Op::EchoAck) => {
                            debug!("received echo ack");
                            self.state.borrow_mut().last_ack = Some(Instant::now());
                        }
                        Ok(Op::IpData) => {
                            self.state.borrow_mut().last_rx = Some(Instant::now());
                            self.forward_local(ipdata::Packet::new(msg.payload()?)?.payload()?)?;
                        }
                        Ok(Op::EchoReq) => {
                            debug!("received echo req(from old version server?)");
                            self.state.borrow_mut().last_ack = Some(Instant::now());
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
        } = *self.config;

        let State {
            last_rebind,
            last_connect,
            last_ack,
            last_rx,
            last_echo,
            ..
        } = *self.state.borrow();

        if check_timeout(last_ack, &reconnect_timeout)
            && check_timeout(last_rx, &reconnect_timeout)
            && check_timeout(last_connect, &reconnect_timeout)
        {
            if rebind && check_timeout(last_rebind, &rebind_timeout) {
                info!("Rebind...");
                self.state.borrow_mut().last_rebind = Some(Instant::now());
                if let Some(ref factory) = self.rt.socket_factory {
                    match factory.create_socket() {
                        Ok(socket) => {
                            debug!("rebind to {:}", socket.local_addr()?);
                            self.rt.with_socket(socket);
                        }
                        Err(e) => warn!("rebind fail, {:}", e),
                    }
                }
            };

            info!("Reconnect...");
            self.state.borrow_mut().last_connect = Some(Instant::now());
            if let Some(server_addrs) = &self.config.server_addrs {
                self.server_index = (self.server_index + 1) % server_addrs.len();
                let server_addr = &server_addrs[self.server_index];
                if let Some(s) = self.socket() {
                    //ignore failure
                    let _ = s
                        .connect(&build_server_addr(server_addr))
                        .map_err(|e| warn!("{:?}", e));
                }
            }
        }

        if check_timeout(last_echo, &keepalive_interval) {
            self.state.borrow_mut().last_echo = Some(Instant::now());
            self.send_echo()?;
        }

        Ok(())
    }

    fn handle_control_connection(&self, fd: RawFd) {
        let mut us = unsafe { UnixStream::from_raw_fd(fd) };
        //ignore failure
        let _ = us.write(self.to_string().as_bytes());
    }
}
