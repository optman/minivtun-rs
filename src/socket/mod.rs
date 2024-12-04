mod native;
pub use native::NativeSocket;

#[cfg(feature = "holepunch")]
mod rndz;
#[cfg(feature = "holepunch")]
pub use self::rndz::RndzSocket;

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
}

pub type Socket = dyn XSocket;
