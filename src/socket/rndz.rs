use crate::socket::XSocket;
use rndz::udp as rndz;
use std::io::Result;
use std::net::{SocketAddr, UdpSocket};
use std::ops::{Deref, DerefMut};
use std::time::{Duration, Instant};

pub struct RndzSocket {
    rndz: rndz::Client,
    socket: Option<UdpSocket>,
}

impl RndzSocket {
    pub fn new(server: &str, id: &str, local_addr: Option<SocketAddr>) -> Result<Self> {
        let rndz = rndz::Client::new(server, id, local_addr)?;
        Self::_new(rndz)
    }
    pub fn new_with_socket(server: &str, id: &str, svr_sk: UdpSocket) -> Result<Self> {
        let rndz = rndz::Client::new_with_socket(server, id, svr_sk)?;
        Self::_new(rndz)
    }
    fn _new(rndz: rndz::Client) -> Result<Self> {
        Ok(Self { rndz, socket: None })
    }
    pub fn connect(&mut self, target_id: &str) -> Result<()> {
        self.socket = Some(self.rndz.connect(target_id)?);
        Ok(())
    }
    pub fn listen(&mut self) -> Result<()> {
        self.socket = Some(self.rndz.listen()?);
        Ok(())
    }
}

impl Deref for RndzSocket {
    type Target = UdpSocket;
    fn deref(&self) -> &Self::Target {
        self.socket.as_ref().unwrap()
    }
}

impl DerefMut for RndzSocket {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.socket.as_mut().unwrap()
    }
}

impl XSocket for RndzSocket {
    fn is_stale(&self) -> bool {
        self.rndz
            .last_pong()
            .map(|v| v.elapsed() > Duration::from_secs(60))
            .unwrap_or(false)
    }

    fn last_health(&self) -> Option<Instant> {
        self.rndz.last_pong()
    }
}
