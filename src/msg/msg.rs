use crate::cryptor::Cryptor;
use crate::error::{Error, Result};
use crate::msg::builder::{Builder as Build, Finalization};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use num_enum::TryFromPrimitive;
use packet::{buffer::Dynamic, Buffer};
use std::convert::TryFrom;
use std::io::Cursor;

#[derive(PartialEq, Debug, TryFromPrimitive)]
#[repr(u8)]
pub enum Op {
    EchoReq,
    IpData,
    Disconnect,
    EchoAck,
}

const HEADER_SIZE: usize = 20;

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
    pub fn seq(mut self, seq: u16) -> Result<Self> {
        Cursor::new(&mut self.buffer.data_mut()[2..]).write_u16::<BigEndian>(seq)?;
        Ok(self)
    }

    pub fn op(mut self, op: Op) -> Result<Self> {
        self.kind = true;
        if op == Op::Disconnect {
            self.payload = true;
        }
        self.buffer.data_mut()[0] = op as u8;
        Ok(self)
    }

    pub fn payload<'a, T: IntoIterator<Item = &'a u8>>(mut self, value: T) -> Result<Self> {
        if self.payload {
            Err(Error::InvalidPacket)?
        }

        self.payload = true;

        for byte in value {
            self.buffer.more(1)?;
            *self.buffer.data_mut().last_mut().unwrap() = *byte;
        }

        Ok(self)
    }

    pub fn echo_req(self) -> Result<crate::msg::echo::Builder<B>> {
        let new_self = self.op(Op::EchoReq)?;
        let mut builder = crate::msg::echo::Builder::with(new_self.buffer)?;
        builder.finalizer().extend(new_self.finalizer);

        Ok(builder)
    }

    pub fn echo_ack(self) -> Result<crate::msg::echo::Builder<B>> {
        let new_self = self.op(Op::EchoAck)?;
        let mut builder = crate::msg::echo::Builder::with(new_self.buffer)?;
        builder.finalizer().extend(new_self.finalizer);
        Ok(builder)
    }

    pub fn disconnect(self) -> Result<Self> {
        Ok(self.op(Op::Disconnect)?)
    }

    pub fn ip_data(self) -> Result<crate::msg::ipdata::Builder<B>> {
        let new_self = self.op(Op::IpData)?;
        let mut builder = crate::msg::ipdata::Builder::with(new_self.buffer)?;
        builder.finalizer().extend(new_self.finalizer);
        Ok(builder)
    }

    pub fn cryptor(mut self, mut cryptor: Box<dyn Cryptor>) -> Result<Self> {
        if cryptor.is_plain() {
            return Ok(self);
        }

        self.finalizer.add(move |mut buffer| {
            buffer[4..20].copy_from_slice(cryptor.auth_key());
            Ok(cryptor.encrypt(&buffer)?)
        });

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

    pub fn with_cryptor(buffer: B, mut cryptor: Box<dyn Cryptor>) -> Result<Packet<Vec<u8>>> {
        if cryptor.is_plain() {
            return Ok(Packet::new(buffer.as_ref().to_vec())?);
        }

        let out = cryptor.decrypt(buffer.as_ref())?;
        if out[4..20] != *cryptor.auth_key() {
            Err(Error::InvalidPacket)?
        }

        Packet::new(out)
    }

    pub fn seq(&self) -> Result<u16> {
        let mut buf = Cursor::new(&self.buffer.as_ref()[2..]);
        let seq = buf.read_u16::<BigEndian>()?;
        Ok(seq)
    }

    pub fn op(&self) -> Result<Op> {
        let op: u8 = self.buffer.as_ref()[0];
        let op = Op::try_from(op).map_err(|_| Error::InvalidPacket)?;
        Ok(op)
    }

    pub fn payload(&self) -> Result<&[u8]> {
        Ok(&self.buffer.as_ref()[HEADER_SIZE..])
    }
}

#[cfg(test)]
mod tests {
    use self::super::*;
    use crate::cryptor::Aes128Cryptor;
    use crate::msg::{echo, ipdata};
    use core::iter::repeat;
    use std::convert::TryInto;

    #[test]
    fn test() {
        let key: Vec<u8> = repeat(1).take(16).collect();
        let key: [u8; 16] = key.try_into().unwrap();

        let cryptor = Aes128Cryptor::new(&key, 16);

        let buf = Builder::default()
            .seq(1)
            .unwrap()
            .op(Op::EchoAck)
            .unwrap()
            .payload(&[0; 12])
            .unwrap()
            .cryptor(Box::new(cryptor.clone()))
            .unwrap()
            .build()
            .unwrap();

        assert_eq!(buf.len(), 20 + 12); //align to block size

        let p = Packet::with_cryptor(buf, Box::new(cryptor.clone())).unwrap();
        assert_eq!(p.seq().unwrap(), 1);

        let buf = Builder::default()
            .cryptor(Box::new(cryptor.clone()))
            .unwrap()
            .seq(1)
            .unwrap()
            .echo_req()
            .unwrap()
            .id(2)
            .unwrap()
            .build()
            .unwrap();

        assert_eq!(buf.len(), 20 + 24 + 4 /*padding*/);

        let p = Packet::with_cryptor(buf, Box::new(cryptor.clone())).unwrap();

        assert_eq!(p.op().unwrap(), Op::EchoReq);

        let p = echo::Packet::new(p.payload().unwrap()).unwrap();
        assert_eq!(p.id().unwrap(), 2);

        Builder::default().disconnect().unwrap().build().unwrap();

        let buf = Builder::default()
            .ip_data()
            .unwrap()
            .kind(ipdata::Kind::V4)
            .unwrap()
            .payload(&[0; 6])
            .unwrap()
            .build()
            .unwrap();

        assert_eq!(buf.len(), 20 + 4 + 6);
    }
}
