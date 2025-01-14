use super::encrypt::NO_ENCRYPT;
use super::Encryptor;
use crate::cryptor::Cryptor;
use crate::error::{Error, Result};
use crate::msg::builder::{Builder as Build, Finalizer};
use byteorder::{BigEndian, ByteOrder};
use num_enum::TryFromPrimitive;
use packet::{buffer::Dynamic, Buffer};
use std::convert::TryFrom;

#[derive(PartialEq, Eq, Debug, TryFromPrimitive)]
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
    finalizer: Encryptor<'a>,
}

impl Default for Builder<'_, Dynamic> {
    fn default() -> Self {
        Self::with(Dynamic::default()).unwrap()
    }
}

impl<'a, B: Buffer> Build<B> for Builder<'a, B> {
    fn build(self) -> Result<Vec<u8>> {
        if !self.kind | !self.payload {
            Err(Error::InvalidPacket)?
        }

        self.finalizer.finalize(self.buffer)
    }
}

impl<'a, B: Buffer> Builder<'a, B> {
    pub fn with(mut buf: B) -> Result<Builder<'a, B>> {
        buf.next(HEADER_SIZE)?;
        Ok(Builder {
            buffer: buf,
            kind: false,
            payload: false,
            finalizer: NO_ENCRYPT,
        })
    }

    pub fn with_cryptor(mut self, cryptor: Option<&'a dyn Cryptor>) -> Result<Builder<'a, B>> {
        self.finalizer = Encryptor::new(cryptor);
        Ok(self)
    }

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

    pub fn echo_req(self) -> Result<crate::msg::echo::Builder<Encryptor<'a>, B>> {
        let new_self = self.op(Op::EchoReq)?;
        crate::msg::echo::Builder::with(new_self.buffer, new_self.finalizer)
    }

    pub fn echo_ack(self) -> Result<crate::msg::echo::Builder<Encryptor<'a>, B>> {
        let new_self = self.op(Op::EchoAck)?;
        crate::msg::echo::Builder::with(new_self.buffer, new_self.finalizer)
    }

    pub fn disconnect(self) -> Result<Self> {
        self.op(Op::Disconnect)
    }

    pub fn ip_data(self) -> Result<crate::msg::ipdata::Builder<Encryptor<'a>, B>> {
        let new_self = self.op(Op::IpData)?;
        crate::msg::ipdata::Builder::with(new_self.buffer, new_self.finalizer)
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

    pub fn with_cryptor<'a>(
        buffer: &'a mut [u8],
        cryptor: Option<&dyn Cryptor>,
    ) -> Result<Packet<&'a [u8]>> {
        if buffer.len() < HEADER_SIZE {
            Err(Error::InvalidPacket)?
        }

        let out = match cryptor {
            None => buffer,
            Some(cryptor) => {
                let out = cryptor.decrypt(buffer)?;
                if out[4..20] != *cryptor.auth_key() {
                    Err(Error::InvalidPacket)?
                };

                out
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
        let cryptor = Aes128Cryptor::new(&key);

        let mut buf = Builder::default()
            .with_cryptor(Some(&cryptor))
            .unwrap()
            .seq(1)
            .unwrap()
            .op(Op::EchoAck)
            .unwrap()
            .payload(&[0; 12])
            .unwrap()
            .build()
            .unwrap();

        assert_eq!(buf.len(), 20 + 12); //align to block size

        let p = Packet::<&[u8]>::with_cryptor(&mut buf, Some(&cryptor)).unwrap();
        assert_eq!(p.seq().unwrap(), 1);

        let mut buf = Builder::default()
            .with_cryptor(Some(&cryptor))
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

        let p = Packet::<&[u8]>::with_cryptor(&mut buf, Some(&cryptor)).unwrap();
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
