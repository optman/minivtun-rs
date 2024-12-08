use super::{SocketConfigure, SocketFactory};
use crate::{Config, Error, RndzSocket, RndzSocketBuilder, Socket};
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
        let builder = || -> Result<RndzSocket, Error> {
            let sk_cfg = self.sk_cfg.clone().map(|sk_cfg| {
                let sk_cfg = SharedSocketConfigure { sk_cfg };
                Box::new(sk_cfg) as Box<dyn SocketConfigure>
            });

            let builder = RndzSocketBuilder::new(rndz.server.clone(), rndz.local_id.clone())
                .with_socket_configure(sk_cfg)
                .with_local_address(config.listen_addr);

            let build = || {
                if let Some(ref remote_id) = rndz.remote_id {
                    builder.connect(remote_id)
                } else {
                    builder.listen()
                }
            };

            let socket = build().inspect_err(|e| {
                log::error!("rndz create socket fail, {:}", e);
            })?;

            Ok(socket)
        };

        let socket = builder()?;

        Ok(Box::new(socket))
    }
}
