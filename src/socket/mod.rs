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
    fn is_stale(&self) -> bool {
        false
    }

    fn last_health(&self) -> Option<Instant> {
        None
    }
}

pub type Socket = Box<dyn XSocket>;
