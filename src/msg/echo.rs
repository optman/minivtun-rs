use super::encrypt::NO_ENCRYPT;
use super::Encryptor;
use crate::error::{Error, Result};
use crate::msg::builder::{Builder as Build, Finalizer};
use byteorder::{BigEndian, ByteOrder};
use packet::{buffer::Dynamic, Buffer};
use std::net::{Ipv4Addr, Ipv6Addr};

const PACKET_SIZE: usize = 24;

pub struct Builder<F: Finalizer<B>, B: Buffer> {
    buffer: B,
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
        buf.next(PACKET_SIZE)?;
        Ok(Builder {
            buffer: buf,
            finalizer,
        })
    }
    pub fn id(mut self, id: u32) -> Result<Self> {
        BigEndian::write_u32(&mut self.buffer.data_mut()[20..], id);
        Ok(self)
    }

    pub fn ipv4_addr(mut self, addr: Ipv4Addr) -> Result<Self> {
        self.buffer.data_mut()[0..4].copy_from_slice(&addr.octets());
        Ok(self)
    }

    pub fn ipv6_addr(mut self, addr: Ipv6Addr) -> Result<Self> {
        self.buffer.data_mut()[4..20].copy_from_slice(&addr.octets());
        Ok(self)
    }
}

pub struct Packet<B> {
    buffer: B,
}

impl<B: AsRef<[u8]>> Packet<B> {
    pub fn new(buf: B) -> Result<Self> {
        if buf.as_ref().len() < PACKET_SIZE {
            Err(Error::InvalidPacket)?
        }
        Ok(Self { buffer: buf })
    }

    pub fn id(&self) -> Result<u32> {
        Ok(BigEndian::read_u32(&self.buffer.as_ref()[20..]))
    }

    pub fn ip_addr(&self) -> Result<(Ipv4Addr, Ipv6Addr)> {
        let buf = self.buffer.as_ref();
        Ok((
            BigEndian::read_u32(&buf[0..4]).into(),
            BigEndian::read_u128(&buf[4..20]).into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use self::super::*;

    #[test]
    fn test() {
        let addr4 = "1.2.3.4".parse().unwrap();
        let addr6 = "2::1".parse().unwrap();
        let buf = Builder::default()
            .id(1)
            .unwrap()
            .ipv4_addr(addr4)
            .unwrap()
            .ipv6_addr(addr6)
            .unwrap()
            .build()
            .unwrap();

        assert_eq!(buf.len(), 24);

        let p = Packet::new(buf).unwrap();
        assert_eq!(p.id().unwrap(), 1);
        assert_eq!(p.ip_addr().unwrap(), (addr4, addr6));
    }
}
