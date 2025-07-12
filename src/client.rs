use crate::config::Config;
use crate::poll;
use crate::util::source_ip;
use crate::Runtime;
use crate::{
    msg::{Builder, IpDataKind, IpDataPacket, MsgBuilder, MsgPacket, Op},
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
use std::io::{Read, Write};
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
    pub(crate) server_index: RefCell<usize>,
}

impl Client {
    pub fn new(config: Rc<Config>, rt: Runtime) -> Result<Self> {
        Ok(Self {
            config,
            rt,
            state: Default::default(),
            server_index: Default::default(),
        })
    }

    pub fn run(self) -> Result<()> {
        self.connect();
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

    fn get_next_server_addr(&self) -> Option<String> {
        let addrs = match self.config.server_addrs {
            Some(ref addrs) => addrs,
            None => return None,
        };

        let idx = *self.server_index.borrow();
        *self.server_index.borrow_mut() = (idx + 1) % addrs.len();
        Some(build_server_addr(addrs.get(idx).unwrap()))
    }

    fn rebind(&mut self) -> Result<()> {
        self.state.borrow_mut().last_rebind = Some(Instant::now());
        if let Some(ref factory) = self.rt.socket_factory {
            match factory.create_socket() {
                Ok(socket) => {
                    info!("rebind to {:}", socket.local_addr().unwrap());
                    self.rt.with_socket(socket);
                    Ok(())
                }
                Err(e) => {
                    warn!("rebind fail, {:}", e);
                    Err(e.into())
                }
            }
        } else {
            warn!("rebind fail, socket factory not set");
            Err("socket factory not set".into())
        }
    }

    fn connect(&self) {
        let s = match self.socket() {
            Some(s) => s,
            None => return,
        };

        if let Some(server_addr) = self.get_next_server_addr() {
            //ignore failure
            let _ = s.connect(&server_addr).inspect_err(|e| warn!("{:?}", e));
        } else {
            //it is possible that the socket is already connected
        };

        if let Ok(peer_addr) = s.peer_addr() {
            info!("connected to {:}", peer_addr);
        };

        self.state.borrow_mut().last_connect = Some(Instant::now());
    }

    fn forward_remote(&self, kind: IpDataKind, pkt: &[u8]) -> Result<()> {
        let s = match self.socket() {
            Some(s) => s,
            None => return Ok(()),
        };

        let msg = self.new_msg()?.ip_data()?.kind(kind)?.payload(pkt)?;

        //ignore failure
        let _ = s.send(&msg.build()?);

        self.state.borrow_mut().tx_bytes += pkt.len() as u64;

        Ok(())
    }

    fn forward_local(&self, pkt: &[u8]) -> Result<()> {
        //is valid ip packet?
        let _ = source_ip(pkt)?;

        //ignore failure
        let _ = write(self.tun(), pkt);

        self.state.borrow_mut().rx_bytes += pkt.len() as u64;

        Ok(())
    }

    fn send_echo(&self) -> Result<()> {
        let s = match self.socket() {
            Some(s) => s,
            None => return Ok(()),
        };

        let mut msg = self
            .new_msg()?
            .echo_req()?
            .id(self.state.borrow().gen_id())?;

        if let Some(ref addr4) = self.config.loc_tun_in {
            msg = msg.ipv4_addr(addr4.addr())?;
        }

        if let Some(ref addr6) = self.config.loc_tun_in6 {
            msg = msg.ipv6_addr(addr6.addr())?;
        }

        //ignore failure
        let _ = s.send(&msg.build()?);

        Ok(())
    }

    fn new_msg(&self) -> Result<MsgBuilder> {
        let builder = MsgBuilder::default()
            .with_cryptor(self.config.cryptor())?
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
            4 => self.forward_remote(IpDataKind::V4, &buf[..size])?,
            6 => self.forward_remote(IpDataKind::V6, &buf[..size])?,
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
                match MsgPacket::<&[u8]>::with_cryptor(&mut buf[..size], self.config.cryptor()) {
                    Ok(msg) => match msg.op() {
                        Ok(Op::EchoAck) => {
                            debug!("received echo ack");
                            self.state.borrow_mut().last_ack = Some(Instant::now());
                        }
                        Ok(Op::IpData) => {
                            self.state.borrow_mut().last_rx = Some(Instant::now());
                            self.forward_local(IpDataPacket::new(msg.payload()?)?.payload()?)?;
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
                let _ = self.rebind();
            };

            self.connect();
        }

        if check_timeout(last_echo, &keepalive_interval) {
            self.state.borrow_mut().last_echo = Some(Instant::now());
            self.send_echo()?;
        }

        Ok(())
    }

    fn handle_control_connection(&mut self, fd: RawFd) {
        let mut us = unsafe { UnixStream::from_raw_fd(fd) };
        let mut buf = [0u8; 64];

        // First try to read from the socket in case it's a command
        if let Ok(n) = us.read(&mut buf) {
            let resp = if let Ok(s) = std::str::from_utf8(&buf[..n]) {
                if s.trim() == "change-server" {
                    info!("Received change-server command, switching to next server");
                    match self.rebind() {
                        Ok(_) => {
                            self.connect();
                            "Changed server\n".to_string()
                        }
                        Err(e) => format!("Failed to change server: {:?}\n", e),
                    }
                } else if s.trim() == "show-info" {
                    self.to_string()
                } else {
                    format!("Unknown command: {}\n", s.trim())
                }
            } else {
                "Invalid UTF-8 sequence\n".to_string()
            };

            let _ = us.write(resp.as_bytes());
        }
    }
}
