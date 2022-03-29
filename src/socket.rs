use rndz::udp as rndz;
use std::io::Result;
use std::net::SocketAddr;
use std::net::UdpSocket;
use std::os::unix::io::{AsRawFd, RawFd};

pub trait Socket {
    fn set_nonblocking(&mut self, _: bool) -> Result<()>;
    fn as_raw_fd(&self) -> RawFd;
    fn send(&mut self, _: &[u8]) -> Result<usize>;
    fn send_to(&mut self, _: &[u8], addr: SocketAddr) -> Result<usize>;
    fn recv_from(&mut self, _: &mut [u8]) -> Result<(usize, SocketAddr)>;
    fn local_addr(&self) -> Result<SocketAddr>;
}

pub trait AsUdpSocket {
    fn as_udp_mut(&mut self) -> &mut UdpSocket;
    fn as_udp(&self) -> &UdpSocket;
    fn connect(&mut self, addr: &str) -> Result<()>;
    fn listen(&mut self) -> Result<()>;
}

impl Socket for dyn AsUdpSocket {
    fn set_nonblocking(&mut self, b: bool) -> Result<()> {
        self.as_udp_mut().set_nonblocking(b)
    }

    fn as_raw_fd(&self) -> RawFd {
        self.as_udp().as_raw_fd()
    }

    fn send(&mut self, data: &[u8]) -> Result<usize> {
        self.as_udp_mut().send(data)
    }

    fn send_to(&mut self, data: &[u8], addr: SocketAddr) -> Result<usize> {
        self.as_udp_mut().send_to(data, addr)
    }

    fn recv_from(&mut self, data: &mut [u8]) -> Result<(usize, SocketAddr)> {
        self.as_udp_mut().recv_from(data)
    }

    fn local_addr(&self) -> Result<SocketAddr> {
        self.as_udp().local_addr()
    }
}

pub struct PlainSocket(UdpSocket);

impl PlainSocket {
    pub fn new(local_addr: SocketAddr) -> Result<Self> {
        Ok(PlainSocket(UdpSocket::bind(local_addr)?))
    }
}

impl AsUdpSocket for PlainSocket {
    fn as_udp_mut(&mut self) -> &mut UdpSocket {
        &mut self.0
    }
    fn as_udp(&self) -> &UdpSocket {
        &self.0
    }
    fn connect(&mut self, addr: &str) -> Result<()> {
        self.0.connect(addr)
    }
    fn listen(&mut self) -> Result<()> {
        Ok(())
    }
}

pub struct RndzSocket {
    rndz: rndz::Client,
    socket: UdpSocket,
}

impl RndzSocket {
    pub fn new(server: &str, id: &str, local_addr: Option<SocketAddr>) -> Result<Self> {
        let rndz = rndz::Client::new(server, id, local_addr)?;
        let socket = rndz.as_socket();
        Ok(Self {
            rndz: rndz,
            socket: socket,
        })
    }
}

impl AsUdpSocket for RndzSocket {
    fn as_udp_mut(&mut self) -> &mut UdpSocket {
        &mut self.socket
    }
    fn as_udp(&self) -> &UdpSocket {
        &self.socket
    }
    fn connect(&mut self, addr: &str) -> Result<()> {
        self.rndz.connect(addr)
    }
    fn listen(&mut self) -> Result<()> {
        self.rndz.listen()
    }
}
