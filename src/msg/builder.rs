use crate::error::Result;
use packet::Buffer;

/// A packet `Builder`.
pub trait Builder<B: Buffer> {
    /// Create a new packet `Builder` with the given buffer.
    fn with(buffer: B) -> Result<Self>
    where
        Self: Sized;

    /// Build the packet
    fn build(self) -> Result<Vec<u8>>;
}

/// A trait for transforming built packets
pub trait PacketTransform {
    fn transform(&self, data: Vec<u8>) -> Result<Vec<u8>>;
}

/// Extension trait to add transform capabilities to builders
pub trait BuilderExt<B: Buffer>: Builder<B> {
    fn transform<T: PacketTransform>(self, transform: &T) -> Result<Vec<u8>>
    where
        Self: Sized,
    {
        let data = self.build()?;
        transform.transform(data)
    }
}

// Implement BuilderExt for all Builder types
impl<T, B> BuilderExt<B> for T
where
    T: Builder<B>,
    B: Buffer,
{
}
