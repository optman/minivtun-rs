use crate::socket::XSocket;
use std::net::UdpSocket;
use std::ops::{Deref, DerefMut};

pub struct NativeSocket(UdpSocket);
impl NativeSocket {
    pub fn new(s: UdpSocket) -> Self {
        Self(s)
    }
}

impl Deref for NativeSocket {
    type Target = UdpSocket;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for NativeSocket {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl XSocket for NativeSocket {
    fn is_stale(&self) -> bool {
        false
    }

    fn last_health(&self) -> Option<std::time::Instant> {
        Some(std::time::Instant::now())
    }

    fn connect(&self, dst: &str) -> std::io::Result<()> {
        self.0.connect(dst)
    }
}
