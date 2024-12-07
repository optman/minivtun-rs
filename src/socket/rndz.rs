use crate::socket::XSocket;
use rndz::udp as rndz;
use std::io::Result;
use std::net::{SocketAddr, UdpSocket};
use std::ops::{Deref, DerefMut};
use std::time::{Duration, Instant};

pub use rndz::SocketConfigure;

pub struct RndzSocket {
    rndz: Option<rndz::Client>,
    socket: UdpSocket,
}

pub struct RndzSocketBuilder {
    server: String,
    id: String,
    local_addr: Option<SocketAddr>,
    sk_cfg: Option<Box<dyn SocketConfigure>>,
}

impl RndzSocketBuilder {
    pub fn new(server: String, id: String) -> Self {
        Self {
            server,
            id,
            local_addr: None,
            sk_cfg: None,
        }
    }
    pub fn with_local_address(&mut self, local_addr: Option<SocketAddr>) -> &mut Self {
        self.local_addr = local_addr;
        self
    }

    pub fn with_socket_configure(&mut self, sk_cfg: Option<Box<dyn SocketConfigure>>) -> &mut Self {
        self.sk_cfg = sk_cfg;
        self
    }

    fn into_rndz(self) -> Result<rndz::Client> {
        rndz::Client::new(&self.server, &self.id, self.local_addr, self.sk_cfg)
    }

    pub fn connect(self, target_id: &str) -> Result<RndzSocket> {
        let socket = self.into_rndz()?.connect(target_id)?;
        Ok(RndzSocket { rndz: None, socket })
    }

    pub fn listen(self) -> Result<RndzSocket> {
        let mut rndz = self.into_rndz()?;
        let socket = rndz.listen()?;
        Ok(RndzSocket {
            rndz: Some(rndz),
            socket,
        })
    }
}

impl Deref for RndzSocket {
    type Target = UdpSocket;
    fn deref(&self) -> &Self::Target {
        &self.socket
    }
}

impl DerefMut for RndzSocket {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.socket
    }
}

impl XSocket for RndzSocket {
    fn is_stale(&self) -> bool {
        self.rndz
            .as_ref()
            .and_then(|r| r.last_pong())
            .map(|v| v.elapsed() > Duration::from_secs(60))
            .unwrap_or(false)
    }

    fn last_health(&self) -> Option<Instant> {
        self.rndz.as_ref().and_then(|r| r.last_pong())
    }

    fn connect(&self, _: &str) -> std::io::Result<()> {
        //self.socket is already connected
        Ok(())
    }
}
