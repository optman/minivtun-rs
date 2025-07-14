use crate::{util::choose_bind_addr, Config, Error, NativeSocket, Socket, SocketFactory};
use std::net::UdpSocket;
use std::rc::Rc;

pub(crate) struct NativeSocketFactory {
    pub(crate) config: Rc<Config>,
}

impl SocketFactory for NativeSocketFactory {
    fn create_socket(&self, server_addr: Option<&str>) -> Result<Box<Socket>, Error> {
        let config = &self.config;
        let bind_addr = match config.listen_addr {
            Some(addr) => addr,
            None => choose_bind_addr(server_addr)?,
        };
        let socket = UdpSocket::bind(bind_addr).expect("listen address bind fail.");

        Ok(Box::new(NativeSocket::new(socket)))
    }
}
