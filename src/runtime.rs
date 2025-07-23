use crate::default_socket_configure;
use crate::SocketConfigure;

#[cfg(feature = "holepunch")]
use crate::socket::DummySocket;
use crate::Error;
use crate::{default_socket_factory, Config, Socket, SocketFactory};
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixListener;
use std::rc::Rc;

pub struct Runtime {
    pub(crate) tun_fd: OwnedFd,
    pub(crate) control_fd: Option<UnixListener>,
    pub(crate) exit_signal: Option<OwnedFd>,
    pub(crate) socket: Option<Box<Socket>>,
    pub(crate) socket_factory: Option<Box<dyn SocketFactory>>,
}
impl Runtime {
    pub fn with_socket(&mut self, s: Box<Socket>) -> &mut Self {
        self.socket = Some(s);
        self
    }

    pub fn socket(&self) -> Option<&Socket> {
        self.socket.as_deref()
    }
}

pub struct RuntimeBuilder {
    config: Rc<Config>,
    tun_fd: Option<OwnedFd>,
    control_fd: Option<UnixListener>,
    exit_signal: Option<OwnedFd>,
    socket: Option<Box<Socket>>,
    socket_factory: Option<Box<dyn SocketFactory>>,
    socket_configure: Option<Box<dyn SocketConfigure>>,
}

impl RuntimeBuilder {
    pub fn new(config: Rc<Config>) -> Self {
        Self {
            config,
            tun_fd: None,
            control_fd: None,
            exit_signal: None,
            socket: None,
            socket_factory: None,
            socket_configure: None,
        }
    }
    pub fn build(mut self) -> Result<Runtime, Error> {
        let socket_configure = self
            .socket_configure
            .take()
            .or_else(|| default_socket_configure(self.config.clone()));

        let socket_factory = self
            .socket_factory
            .take()
            .unwrap_or_else(|| default_socket_factory(self.config.clone(), socket_configure));

        let socket = self
            .socket
            .take()
            .map_or_else(
                || {
                    let server_addrs = self.config.get_server_addrs();
                    socket_factory.create_socket(if self.config.is_client() {
                        //rndz client use only one server each time
                        server_addrs.map(|addrs| addrs[0..1].to_vec())
                    } else {
                        server_addrs
                    })
                },
                Ok,
            )
            .map(Some)
            .or_else(|e| {
                if self.config.wait_dns {
                    log::warn!("waiting network ready...");
                    #[cfg(feature = "holepunch")]
                    if self.config.is_holepunch() && !self.config.is_client() {
                        //for holepunch server, we create a dummy socket
                        use std::net::UdpSocket;
                        let bind_addr = if let Some(addr) = self.config.listen_addr {
                            addr
                        } else {
                            "0.0.0.0:0".parse().unwrap()
                        };

                        let socket = UdpSocket::bind(bind_addr)
                            .map_err(|e| Error::Other(format!("bind fail: {}", e)))?;
                        socket.set_nonblocking(true).unwrap();
                        let dummy_socket = Box::new(DummySocket::new(socket));
                        return Ok(Some(dummy_socket));
                    }
                    Ok(None)
                } else {
                    Err(e)
                }
            })?;

        Ok(Runtime {
            tun_fd: self.tun_fd.expect("tun fd not set"),
            control_fd: self.control_fd.take(),
            exit_signal: self.exit_signal.take(),
            socket,
            socket_factory: Some(socket_factory),
        })
    }
}

impl RuntimeBuilder {
    pub fn with_socket(&mut self, s: Box<Socket>) -> &mut Self {
        self.socket = Some(s);
        self
    }

    pub fn with_tun_fd(&mut self, fd: OwnedFd) -> &mut Self {
        self.tun_fd = Some(fd);
        self
    }

    pub fn with_socket_factory(&mut self, f: Box<dyn SocketFactory>) -> &mut Self {
        self.socket_factory = Some(f);
        self
    }

    pub fn with_socket_configure(&mut self, f: Box<dyn SocketConfigure>) -> &mut Self {
        self.socket_configure = Some(f);
        self
    }

    pub fn with_control_fd(&mut self, fd: UnixListener) -> &mut Self {
        self.control_fd = Some(fd);
        self
    }

    pub fn with_exit_signal(&mut self, exit_signal: OwnedFd) -> &mut Self {
        self.exit_signal = Some(exit_signal);
        self
    }
}
