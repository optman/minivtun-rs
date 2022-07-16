use std::net::{Ipv4Addr, Ipv6Addr};

use crate::error::{Error, Result};
use crate::msg::builder::{Builder as Build, Finalization};
use byteorder::{BigEndian, ByteOrder};
use packet::{buffer::Dynamic, Buffer};

const PACKET_SIZE: usize = 24;

pub struct Builder<'a, B: Buffer = Dynamic> {
    buffer: B,
    finalizer: Finalization<'a, Vec<u8>>,
}

impl<'a, B: Buffer> Build<'a, B> for Builder<'a, B> {
    fn with(mut buf: B) -> Result<Self> {
        buf.next(PACKET_SIZE)?;
        Ok(Builder {
            buffer: buf,
            finalizer: Default::default(),
        })
    }

    fn finalizer(&mut self) -> &mut Finalization<'a, Vec<u8>> {
        &mut self.finalizer
    }

    fn build(self) -> Result<Vec<u8>> {
        Ok(self
            .finalizer
            .finalize(self.buffer.into_inner().as_mut().to_vec())?)
    }
}

impl<'a> Default for Builder<'a, Dynamic> {
    fn default() -> Self {
        Builder::with(Dynamic::default()).unwrap()
    }
}

impl<'a, B: Buffer> Builder<'_, B> {
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
        let a = Builder::default()
            .id(1)
            .unwrap()
            .ipv4_addr(addr4)
            .unwrap()
            .ipv6_addr(addr6)
            .unwrap();

        let buf = a.build().unwrap();
        assert_eq!(buf.len(), 24);

        let p = Packet::new(buf).unwrap();
        assert_eq!(p.id().unwrap(), 1);
        assert_eq!(p.ip_addr().unwrap(), (addr4, addr6));
    }
}
