use crate::error::Result;
use packet::Buffer;

/// A packet `Builder`.
pub trait Builder {
    //build with finalized
    fn build(self) -> Result<Vec<u8>>;
}

/// A trait for transforming built packets
pub trait Finalizer<B: Buffer> {
    fn finalize(&self, data: B) -> Result<Vec<u8>>;
}
