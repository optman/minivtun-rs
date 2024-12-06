use super::{SocketConfigure, SocketFactory};
use crate::{Config, Error, RndzSocket, Socket};
use std::rc::Rc;

struct SharedSocketConfigure {
    sk_cfg: Rc<Box<dyn SocketConfigure>>,
}

impl SocketConfigure for SharedSocketConfigure {
    fn config_socket(&self, sk: std::os::unix::prelude::RawFd) -> std::io::Result<()> {
        self.sk_cfg.config_socket(sk)
    }
}

pub(crate) struct RndzSocketFacoty {
    pub(crate) config: Rc<Config>,
    pub(crate) sk_cfg: Option<Rc<Box<dyn SocketConfigure>>>,
}

impl SocketFactory for RndzSocketFacoty {
    fn create_socket(&self) -> Result<Box<Socket>, Error> {
        let config = &self.config;
        let rndz = config.rndz.as_ref().expect("rndz config not set");
        let server = &rndz.server;
        let id = &rndz.local_id;
        let builder = || -> Result<RndzSocket, Error> {
            let sk_cfg = self.sk_cfg.clone().map(|sk_cfg| {
                let sk_cfg = SharedSocketConfigure { sk_cfg };
                Box::new(sk_cfg) as Box<dyn SocketConfigure>
            });

            let mut socket =
                RndzSocket::new(server, id, config.listen_addr, sk_cfg).inspect_err(|e| {
                    log::error!("create rndz socket fail, {:?}", e);
                })?;

            if let Some(ref remote_id) = rndz.remote_id {
                socket.connect(remote_id).inspect_err(|e| {
                    log::error!("rndz connect fail, {:}", e);
                })?;
            } else {
                socket.listen()?;
            }

            Ok(socket)
        };

        let socket = builder()?;

        Ok(Box::new(socket))
    }
}
