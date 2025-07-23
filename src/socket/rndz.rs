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
    servers: Vec<String>,
    id: String,
    local_addr: Option<SocketAddr>,
    sk_cfg: Option<Box<dyn SocketConfigure>>,
}

impl RndzSocketBuilder {
    pub fn new(servers: Vec<String>, id: String) -> Self {
        Self {
            servers,
            id,
            local_addr: None,
            sk_cfg: None,
        }
    }
    pub fn with_local_address(mut self, local_addr: Option<SocketAddr>) -> Self {
        self.local_addr = local_addr;
        self
    }

    pub fn with_socket_configure(mut self, sk_cfg: Option<Box<dyn SocketConfigure>>) -> Self {
        self.sk_cfg = sk_cfg;
        self
    }

    fn into_rndz(self) -> Result<rndz::Client> {
        rndz::Client::new(
            &self.servers.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
            &self.id,
            self.local_addr,
            self.sk_cfg,
        )
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
            .map(|r| {
                let pongs = r.last_pong();
                if pongs.is_empty() {
                    return true;
                }
                //check if any pong is older than 60 seconds
                pongs.iter().any(|p| {
                    p.map(|v| v.elapsed() > Duration::from_secs(60))
                        .unwrap_or(true)
                })
            })
            .unwrap_or(false)
    }

    fn last_health(&self) -> Option<Instant> {
        self.rndz.as_ref().and_then(|r| {
            r.last_pong()
                .iter()
                .filter_map(|p| *p)
                .max_by(|a, b| a.cmp(b))
        })
    }

    fn connect(&self, _: &str) -> std::io::Result<()> {
        //self.socket is already connected
        Ok(())
    }
}
