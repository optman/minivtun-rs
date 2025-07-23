use crate::socket::XSocket;
use std::net::UdpSocket;
use std::ops::{Deref, DerefMut};
use std::time::Instant;

pub struct DummySocket(UdpSocket);

impl DummySocket {
    pub fn new(socket: UdpSocket) -> Self {
        Self(socket)
    }
}

impl Deref for DummySocket {
    type Target = UdpSocket;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for DummySocket {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl XSocket for DummySocket {
    fn is_stale(&self) -> bool {
        true
    }

    fn last_health(&self) -> Option<Instant> {
        None
    }

    fn connect(&self, _dst: &str) -> std::io::Result<()> {
        // Dummy socket doesn't need to connect
        Ok(())
    }
}
