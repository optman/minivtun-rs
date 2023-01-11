mod native;
pub use native::NativeSocket;

#[cfg(feature = "holepunch")]
mod rndz;
#[cfg(feature = "holepunch")]
pub use self::rndz::RndzSocket;

use std::net::UdpSocket;
use std::ops::DerefMut;

pub trait XSocket: DerefMut<Target = UdpSocket> {
    fn is_stale(&self) -> bool {
        false
    }
}

pub type Socket = Box<dyn XSocket>;
