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
        let mut out: Option<Cow<'_, [u8]>> = None;
        for finalizer in self.0.into_iter()
        /*.rev()*/
        {
            let inner_out = match out {
                None => match finalizer.finalize(buffer)? {
                    Cow::Borrowed(_) => None,
                    Cow::Owned(b) => Some(Cow::Owned(b)),
                },
                Some(ref mut out) => Some(finalizer.finalize(out.to_mut())?),
            };

            if let Some(Cow::Owned(b)) = inner_out {
                out = Some(Cow::Owned(b));
            }
        }

        let out = match out {
            None => Cow::Borrowed(buffer),
            Some(out) => Cow::Owned(out.into_owned()),
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

#[allow(clippy::from_over_into)]
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
