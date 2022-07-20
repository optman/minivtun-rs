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
use std::borrow::Cow;

/// A finalizer used by builders to complete building the packet, this is
/// usually used to calculate the checksum and update length fields after the
/// whole packet has been created.
pub trait Finalizer {
    /// Run the finalizer on the given buffer.
    fn finalize(&self, buffer: &mut [u8]) -> Result<Vec<u8>>;
}

impl<'a, F: Fn(&mut [u8]) -> Result<Vec<u8>> + 'a> Finalizer for F {
    fn finalize(&self, buffer: &mut [u8]) -> Result<Vec<u8>> {
        self(buffer)
    }
}

/// Takes care of grouping finalizers through the builder chain.
pub struct Finalization<'a>(Vec<&'a dyn Finalizer>);

impl<'a> Default for Finalization<'a> {
    fn default() -> Self {
        Finalization(Default::default())
    }
}

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

    pub fn add_fn<F: Fn(&mut [u8]) -> Result<Vec<u8>>>(&mut self, finalizer: &'a F) {
        self.0.push(finalizer);
    }

    /// Add a serie of finalizers.
    pub fn extend<I: IntoIterator<Item = &'a dyn Finalizer>>(&mut self, finalizers: I) {
        self.0.extend(finalizers.into_iter());
    }

    /// Finalize a buffer.
    pub fn finalize<'b>(self, buffer: &'b mut [u8]) -> Result<Cow<'b, [u8]>> {
        let mut out = None;
        for finalizer in self.0.into_iter()
        /*.rev()*/
        {
            out = match out {
                None => Some(finalizer.finalize(buffer)?),
                Some(mut out) => Some(finalizer.finalize(&mut out)?),
            };
        }

        let out = match out {
            None => Cow::Borrowed(buffer),
            Some(out) => Cow::Owned(out),
        };

        Ok(out)
    }
}

impl<'a> IntoIterator for Finalization<'a> {
    type Item = &'a dyn Finalizer;
    type IntoIter = ::std::vec::IntoIter<&'a dyn Finalizer>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a> Into<Vec<&'a dyn Finalizer>> for Finalization<'a> {
    fn into(self) -> Vec<&'a dyn Finalizer> {
        self.0
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
