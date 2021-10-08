use crate::error::{Error, Result};
use crate::msg::builder::{Builder as Build, Finalization};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use num_enum::TryFromPrimitive;
use packet::{buffer::Dynamic, Buffer};
use std::convert::TryFrom;
use std::io::Cursor;

#[derive(PartialEq, Debug, TryFromPrimitive)]
#[repr(u16)]
pub enum Kind {
    V4 = 0x0800,
    V6 = 0x86dd,
}

const HEADER_SIZE: usize = 4;

pub struct Builder<B: Buffer = Dynamic> {
    buffer: B,
    kind: bool,
    payload: bool,
    finalizer: Finalization<Vec<u8>>,
}

impl<B: Buffer> Build<B> for Builder<B> {
    fn with(mut buf: B) -> Result<Self> {
        buf.next(HEADER_SIZE)?;
        Ok(Builder {
            buffer: buf,
            kind: false,
            payload: false,
            finalizer: Default::default(),
        })
    }

    fn finalizer(&mut self) -> &mut Finalization<Vec<u8>> {
        &mut self.finalizer
    }

    fn build(self) -> Result<Vec<u8>> {
        if !self.kind | !self.payload {
            Err(Error::InvalidPacket)?
        }

        Ok(self
            .finalizer
            .finalize(self.buffer.into_inner().as_mut().to_vec())?)
    }
}

impl Default for Builder<Dynamic> {
    fn default() -> Self {
        Builder::with(Dynamic::default()).unwrap()
    }
}

impl<B: Buffer> Builder<B> {
    pub fn kind(mut self, kind: Kind) -> Result<Self> {
        self.kind = true;
        Cursor::new(&mut self.buffer.data_mut()[0..]).write_u16::<BigEndian>(kind as u16)?;
        Ok(self)
    }

    pub fn payload<'a, T: IntoIterator<Item = &'a u8>>(mut self, value: T) -> Result<Self> {
        if self.payload {
            Err(Error::InvalidPacket)?
        }

        self.payload = true;

        let mut len: u16 = 0;

        for byte in value {
            len += 1;
            self.buffer.more(1)?;
            *self.buffer.data_mut().last_mut().unwrap() = *byte;
        }
        Cursor::new(&mut self.buffer.data_mut()[2..]).write_u16::<BigEndian>(len)?;

        Ok(self)
    }
}

pub struct Packet<B> {
    buffer: B,
}

impl<B: AsRef<[u8]>> Packet<B> {
    pub fn new(buf: B) -> Result<Self> {
        Ok(Self { buffer: buf })
    }

    pub fn kind(&self) -> Result<Kind> {
        let kind = Cursor::new(&self.buffer.as_ref()[0..]).read_u16::<BigEndian>()?;
        let kind = Kind::try_from(kind).map_err(|_| Error::InvalidPacket)?;

        Ok(kind)
    }

    pub fn payload_length(&self) -> Result<u16> {
        Ok(Cursor::new(&self.buffer.as_ref()[2..]).read_u16::<BigEndian>()?)
    }

    pub fn payload(&self) -> Result<&[u8]> {
        Ok(&self.buffer.as_ref()[HEADER_SIZE..HEADER_SIZE + self.payload_length()? as usize])
    }
}

#[cfg(test)]
mod tests {
    use self::super::*;

    #[test]
    fn test() {
        let a = Builder::default()
            .kind(Kind::V4)
            .unwrap()
            .payload(&[0; 6])
            .unwrap();

        let buf = a.build().unwrap();
        assert_eq!(buf.len(), 4 + 6);

        let p = Packet::new(buf).unwrap();
        assert_eq!(p.kind().unwrap(), Kind::V4);
        assert_eq!(p.payload().unwrap().len(), 6);
    }
}
