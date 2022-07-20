use crate::cryptor::Cryptor;
use crate::error::{Error, Result};
use crate::msg::builder::{Builder as Build, Finalization, Finalizer};
use byteorder::{BigEndian, ByteOrder};
use num_enum::TryFromPrimitive;
use packet::{buffer::Dynamic, Buffer};
use std::borrow::Cow;
use std::convert::TryFrom;

#[derive(PartialEq, Debug, TryFromPrimitive)]
#[repr(u8)]
pub enum Op {
    EchoReq,
    IpData,
    Disconnect,
    EchoAck,
}

const HEADER_SIZE: usize = 20;

pub struct Builder<'a, B: Buffer = Dynamic> {
    buffer: B,
    kind: bool,
    payload: bool,
    finalizer: Finalization<'a>,
}

impl<'a, B: Buffer> Build<'a, B> for Builder<'a, B> {
    fn with(mut buf: B) -> Result<Self> {
        buf.next(HEADER_SIZE)?;
        Ok(Builder {
            buffer: buf,
            kind: false,
            payload: false,
            finalizer: Default::default(),
        })
    }

    fn finalizer(&mut self) -> &mut Finalization<'a> {
        &mut self.finalizer
    }

    fn build(self) -> Result<Vec<u8>> {
        if !self.kind | !self.payload {
            Err(Error::InvalidPacket)?
        }

        Ok(self
            .finalizer
            .finalize(self.buffer.into_inner().as_mut())?
            .into_owned())
    }
}

impl<'a> Default for Builder<'a, Dynamic> {
    fn default() -> Self {
        Builder::with(Dynamic::default()).unwrap()
    }
}

impl<'a, B: Buffer> Builder<'a, B> {
    pub fn seq(mut self, seq: u16) -> Result<Self> {
        BigEndian::write_u16(&mut self.buffer.data_mut()[2..], seq);
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

    pub fn payload(mut self, value: &[u8]) -> Result<Self> {
        if self.payload {
            Err(Error::InvalidPacket)?
        }

        self.payload = true;

        let i = self.buffer.length();
        self.buffer.more(value.len())?;
        self.buffer.data_mut()[i..].copy_from_slice(value);

        Ok(self)
    }

    pub fn echo_req(self) -> Result<crate::msg::echo::Builder<'a, B>> {
        let new_self = self.op(Op::EchoReq)?;
        let mut builder = crate::msg::echo::Builder::with(new_self.buffer)?;
        builder.finalizer().extend(new_self.finalizer);

        Ok(builder)
    }

    pub fn echo_ack(self) -> Result<crate::msg::echo::Builder<'a, B>> {
        let new_self = self.op(Op::EchoAck)?;
        let mut builder = crate::msg::echo::Builder::with(new_self.buffer)?;
        builder.finalizer().extend(new_self.finalizer);
        Ok(builder)
    }

    pub fn disconnect(self) -> Result<Self> {
        Ok(self.op(Op::Disconnect)?)
    }

    pub fn ip_data(self) -> Result<crate::msg::ipdata::Builder<'a, B>> {
        let new_self = self.op(Op::IpData)?;
        let mut builder = crate::msg::ipdata::Builder::with(new_self.buffer)?;
        builder.finalizer().extend(new_self.finalizer);
        Ok(builder)
    }

    pub fn cryptor(mut self, cryptor: &'a Option<Box<dyn Cryptor>>) -> Result<Self> {
        match cryptor {
            Some(cryptor) => {
                self.finalizer.add(cryptor);
            }
            None => {}
        }
        Ok(self)
    }
}

impl Finalizer for Box<dyn Cryptor> {
    fn finalize(&self, buffer: &mut [u8]) -> Result<Vec<u8>> {
        buffer[4..20].copy_from_slice(self.auth_key());
        Ok(self.encrypt(&buffer)?)
    }
}

pub struct Packet<B> {
    buffer: B,
}

impl<'a, B: 'a + AsRef<[u8]>> Packet<B> {
    pub fn new(buf: B) -> Result<Self> {
        if buf.as_ref().len() < HEADER_SIZE {
            Err(Error::InvalidPacket)?
        }

        Ok(Self { buffer: buf })
    }

    pub fn with_cryptor(
        buffer: &'a B,
        cryptor: &Option<Box<dyn Cryptor>>,
    ) -> Result<Packet<Cow<'a, [u8]>>> {
        if buffer.as_ref().len() < HEADER_SIZE {
            Err(Error::InvalidPacket)?
        }

        let out = match cryptor {
            None => buffer.as_ref().into(),
            Some(cryptor) => {
                let out = cryptor.decrypt(buffer.as_ref())?;
                if out[4..20] != *cryptor.auth_key() {
                    Err(Error::InvalidPacket)?
                };

                out.into()
            }
        };
        Packet::new(out)
    }

    pub fn seq(&self) -> Result<u16> {
        Ok(BigEndian::read_u16(&self.buffer.as_ref()[2..]))
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

        let cryptor: Option<Box<dyn Cryptor>> = Some(Box::new(Aes128Cryptor::new(&key)));

        let buf = Builder::default()
            .seq(1)
            .unwrap()
            .op(Op::EchoAck)
            .unwrap()
            .payload(&[0; 12])
            .unwrap()
            .cryptor(&cryptor)
            .unwrap()
            .build()
            .unwrap();

        assert_eq!(buf.len(), 20 + 12); //align to block size

        let buf = &buf[..];
        let p = Packet::with_cryptor(&buf, &cryptor).unwrap();
        assert_eq!(p.seq().unwrap(), 1);

        let buf = Builder::default()
            .cryptor(&cryptor)
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

        let buf = &buf[..];
        let p = Packet::with_cryptor(&buf, &cryptor).unwrap();

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
