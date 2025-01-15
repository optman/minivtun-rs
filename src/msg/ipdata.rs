use super::encrypt::NO_ENCRYPT;
use super::Encryptor;
use crate::error::{Error, Result};
use crate::msg::builder::{Builder as Build, Finalizer};
use byteorder::{BigEndian, ByteOrder};
use num_enum::TryFromPrimitive;
use packet::{buffer::Dynamic, Buffer};
use std::convert::TryFrom;

#[derive(PartialEq, Eq, Debug, TryFromPrimitive)]
#[repr(u16)]
pub enum Kind {
    V4 = 0x0800,
    V6 = 0x86dd,
}

const HEADER_SIZE: usize = 4;

pub struct Builder<F: Finalizer<B>, B: Buffer> {
    buffer: B,
    kind: bool,
    payload: bool,
    finalizer: F,
}

impl<'a> Default for Builder<Encryptor<'a>, Dynamic> {
    fn default() -> Self {
        Builder::with(Dynamic::default(), NO_ENCRYPT).unwrap()
    }
}

impl<F: Finalizer<B>, B: Buffer> Build for Builder<F, B> {
    fn build(self) -> Result<Vec<u8>> {
        self.finalizer.finalize(self.buffer)
    }
}

impl<F: Finalizer<B>, B: Buffer> Builder<F, B> {
    pub fn with(mut buf: B, finalizer: F) -> Result<Builder<F, B>> {
        buf.next(HEADER_SIZE)?;
        Ok(Builder {
            buffer: buf,
            kind: false,
            payload: false,
            finalizer,
        })
    }

    pub fn kind(mut self, kind: Kind) -> Result<Self> {
        self.kind = true;
        BigEndian::write_u16(&mut self.buffer.data_mut()[0..], kind as u16);
        Ok(self)
    }

    pub fn payload(mut self, value: &[u8]) -> Result<Self> {
        if self.payload {
            Err(Error::InvalidPacket)?
        }

        self.payload = true;

        let i = self.buffer.length();
        self.buffer.more(value.len())?;
        self.buffer.data_mut()[i..].copy_from_slice(value);

        BigEndian::write_u16(&mut self.buffer.data_mut()[2..], value.len() as u16);

        Ok(self)
    }
}

pub struct Packet<B> {
    buffer: B,
}

impl<B: AsRef<[u8]>> Packet<B> {
    pub fn new(buf: B) -> Result<Self> {
        if buf.as_ref().len() < HEADER_SIZE {
            Err(Error::InvalidPacket)?
        }

        Ok(Self { buffer: buf })
    }

    pub fn kind(&self) -> Result<Kind> {
        let kind = BigEndian::read_u16(&self.buffer.as_ref()[0..]);
        let kind = Kind::try_from(kind).map_err(|_| Error::InvalidPacket)?;

        Ok(kind)
    }

    pub fn payload_length(&self) -> Result<u16> {
        Ok(BigEndian::read_u16(&self.buffer.as_ref()[2..]))
    }

    pub fn payload(&self) -> Result<&[u8]> {
        let valid_len = HEADER_SIZE + self.payload_length()? as usize;
        if self.buffer.as_ref().len() < valid_len {
            Err(Error::InvalidPacket)?
        }

        Ok(&self.buffer.as_ref()[HEADER_SIZE..valid_len])
    }
}

#[cfg(test)]
mod tests {
    use self::super::*;

    #[test]
    fn test() {
        let buf = Builder::default()
            .kind(Kind::V4)
            .unwrap()
            .payload(&[0; 6])
            .unwrap()
            .build()
            .unwrap();

        assert_eq!(buf.len(), 4 + 6);

        let p = Packet::new(buf).unwrap();
        assert_eq!(p.kind().unwrap(), Kind::V4);
        assert_eq!(p.payload().unwrap().len(), 6);
    }
}
