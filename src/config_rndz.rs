use crate::Config;
use crate::Error;
use std::net::UdpSocket;

#[derive(Default)]
pub struct RndzConfig<'a> {
    #[cfg(feature = "holepunch")]
    pub server: Option<String>,
    #[cfg(feature = "holepunch")]
    pub local_id: Option<String>,
    #[cfg(feature = "holepunch")]
    pub remote_id: Option<String>,
    #[cfg(feature = "holepunch")]
    #[allow(clippy::type_complexity)]
    pub svr_sk_builder: Option<&'a dyn Fn(&Config) -> Result<UdpSocket, Error>>,
}

impl<'a> RndzConfig<'a> {
    pub fn with_svr_sk_builder(
        &mut self,
        f: &'a dyn Fn(&Config) -> Result<UdpSocket, Error>,
    ) -> &mut Self {
        self.svr_sk_builder = Some(f);
        self
    }
}
