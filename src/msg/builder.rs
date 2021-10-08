//            DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
//                    Version 2, December 2004
//
// Copyleft (ↄ) meh. <meh@schizofreni.co> | http://meh.schizofreni.co
//
// Everyone is permitted to copy and distribute verbatim or modified
// copies of this license document, and changing it is allowed as long
// as the name is changed.
//
//            DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
//   TERMS AND CONDITIONS FOR COPYING, DISTRIBUTION AND MODIFICATION
//
//  0. You just DO WHAT THE FUCK YOU WANT TO.

use std::fmt;

use packet::Buffer;

use crate::error::Result;

/// A finalizer used by builders to complete building the packet, this is
/// usually used to calculate the checksum and update length fields after the
/// whole packet has been created.
pub trait Finalizer<B> {
    /// Run the finalizer on the given buffer.
    fn finalize(self: Box<Self>, buffer: B) -> Result<B>;
}

impl<B, F: FnOnce(B) -> Result<B>> Finalizer<B> for F {
    fn finalize(self: Box<F>, buffer: B) -> Result<B> {
        let f = *self;
        f(buffer)
    }
}

/// Takes care of grouping finalizers through the builder chain.
pub struct Finalization<B>(Vec<Box<dyn Finalizer<B>>>);

impl<B> Default for Finalization<B> {
    fn default() -> Self {
        Finalization(Default::default())
    }
}

impl<B> fmt::Debug for Finalization<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("builder::Finalization")
            .field("length", &self.0.len())
            .finish()
    }
}

impl<B> Finalization<B> {
    /// Add a new finalizer.
    pub fn add<F: FnOnce(B) -> Result<B> + 'static>(&mut self, finalizer: F) {
        self.0.push(Box::new(finalizer));
    }

    /// Add a serie of finalizers.
    pub fn extend<I: IntoIterator<Item = Box<dyn Finalizer<B>>>>(&mut self, finalizers: I) {
        self.0.extend(finalizers.into_iter());
    }

    /// Finalize a buffer.
    pub fn finalize(self, buffer: B) -> Result<B> {
        let mut b = buffer;
        for finalizer in self.0.into_iter()
        /*.rev()*/
        {
            b = finalizer.finalize(b)?;
        }

        Ok(b)
    }
}

impl<B> IntoIterator for Finalization<B> {
    type Item = Box<dyn Finalizer<B>>;
    type IntoIter = ::std::vec::IntoIter<Box<dyn Finalizer<B>>>;

    fn into_iter(self) -> ::std::vec::IntoIter<Box<dyn Finalizer<B>>> {
        self.0.into_iter()
    }
}

impl<B> Into<Vec<Box<dyn Finalizer<B>>>> for Finalization<B> {
    fn into(self) -> Vec<Box<dyn Finalizer<B>>> {
        self.0
    }
}

/// A packet `Builder`.
pub trait Builder<B: Buffer> {
    /// Create a new packet `Builder` with the given buffer.
    fn with(buffer: B) -> Result<Self>
    where
        Self: Sized;

    /// Access the finalizers.
    fn finalizer(&mut self) -> &mut Finalization<Vec<u8>>;

    /// Build the packet.
    fn build(self) -> Result<Vec<u8>>;
}
