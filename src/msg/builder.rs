use crate::error::Result;
use packet::Buffer;
use std::borrow::Cow;
use std::fmt;

/// A finalizer used by builders to complete building the packet, this is
/// usually used to calculate the checksum and update length fields after the
/// whole packet has been created.
pub trait Finalizer {
    /// Run the finalizer on the given buffer.
    fn finalize<'a>(&self, buffer: &'a mut [u8]) -> Result<Cow<'a, [u8]>>;
}

impl<F: Fn(&mut [u8]) -> Result<Cow<'_, [u8]>>> Finalizer for F {
    fn finalize<'b>(&self, buffer: &'b mut [u8]) -> Result<Cow<'b, [u8]>> {
        self(buffer)
    }
}

/// Takes care of grouping finalizers through the builder chain.
///
#[derive(Default)]
pub struct Finalization<'a>(Vec<&'a dyn Finalizer>);

impl<'a> fmt::Debug for Finalization<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("builder::Finalization")
            .field("length", &self.0.len())
            .finish()
    }
}

impl<'a> Finalization<'a> {
    /// Add a new finalizer.
    pub fn add(&mut self, finalizer: &'a dyn Finalizer) {
        self.0.push(finalizer);
    }

    pub fn add_fn<F: Fn(&mut [u8]) -> Result<Cow<'_, [u8]>>>(&mut self, finalizer: &'a F) {
        self.0.push(finalizer);
    }

    /// Add a serie of finalizers.
    pub fn extend<I: IntoIterator<Item = &'a dyn Finalizer>>(&mut self, finalizers: I) {
        self.0.extend(finalizers);
    }

    /// Finalize a buffer.
    pub fn finalize(self, buffer: &mut [u8]) -> Result<Cow<'_, [u8]>> {
        // Process finalizers in sequence, only allocating when necessary
        self.0
            .into_iter()
            .try_fold(Cow::Borrowed(buffer), |acc, finalizer| {
                match acc {
                    // For borrowed data, use unsafe to get mutable reference without copying
                    Cow::Borrowed(buf) => {
                        #[allow(invalid_reference_casting)]
                        let buf_mut = unsafe {
                            // SAFETY: We know the buffer is mutable from the original &mut parameter,
                            // and we have exclusive access to it through the Cow
                            &mut *(buf as *const [u8] as *mut [u8])
                        };
                        finalizer.finalize(buf_mut)
                    }
                    // If we've already allocated, work with the owned data
                    Cow::Owned(mut owned) => {
                        let result = finalizer.finalize(&mut owned)?;
                        match result {
                            Cow::Borrowed(borrowed) => {
                                let len = borrowed.len();
                                owned.truncate(len);
                                Ok(Cow::Owned(owned))
                            }
                            Cow::Owned(new_owned) => Ok(Cow::Owned(new_owned)),
                        }
                    }
                }
            })
    }
}

impl<'a> IntoIterator for Finalization<'a> {
    type Item = &'a dyn Finalizer;
    type IntoIter = ::std::vec::IntoIter<&'a dyn Finalizer>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

/// A packet `Builder`.
pub trait Builder<'a, B: Buffer> {
    /// Create a new packet `Builder` with the given buffer.
    fn with(buffer: B) -> Result<Self>
    where
        Self: Sized;

    /// Access the finalizers.
    fn finalizer(&mut self) -> &mut Finalization<'a>;

    /// Build the packet.
    fn build(self) -> Result<Vec<u8>>;
}
