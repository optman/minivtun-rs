mod native;
pub use native::NativeSocket;

#[cfg(feature = "holepunch")]
mod dummy;
#[cfg(feature = "holepunch")]
pub use self::dummy::DummySocket;

#[cfg(feature = "holepunch")]
mod rndz;
#[cfg(feature = "holepunch")]
pub use self::rndz::RndzSocket;
#[cfg(feature = "holepunch")]
pub use self::rndz::RndzSocketBuilder;

use std::net::UdpSocket;
use std::ops::DerefMut;
use std::time::Instant;

pub trait XSocket: DerefMut<Target = UdpSocket> {
    /// Check if the socket is stale. Default is always false.
    fn is_stale(&self) -> bool {
        false
    }

    /// Get the last health check instant. Default returns None.
    fn last_health(&self) -> Option<Instant> {
        None
    }
    fn connect(&self, dst: &str) -> std::io::Result<()>;
}

pub type Socket = dyn XSocket;
