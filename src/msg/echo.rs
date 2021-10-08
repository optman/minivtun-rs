use std::convert::TryInto;
use std::io::Cursor;
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::error::{Error, Result};
use crate::msg::builder::{Builder as Build, Finalization};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use packet::{buffer::Dynamic, Buffer};

const PACKET_SIZE: usize = 24;

pub struct Builder<B: Buffer = Dynamic> {
    buffer: B,
    finalizer: Finalization<Vec<u8>>,
}

impl<B: Buffer> Build<B> for Builder<B> {
    fn with(mut buf: B) -> Result<Self> {
        buf.next(PACKET_SIZE)?;
        Ok(Builder {
            buffer: buf,
            finalizer: Default::default(),
        })
    }

    fn finalizer(&mut self) -> &mut Finalization<Vec<u8>> {
        &mut self.finalizer
    }

    fn build(self) -> Result<Vec<u8>> {
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
    pub fn id(mut self, id: u32) -> Result<Self> {
        Cursor::new(&mut self.buffer.data_mut()[20..]).write_u32::<BigEndian>(id)?;
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
        Ok(Self { buffer: buf })
    }

    pub fn id(&self) -> Result<u32> {
        let mut buf = Cursor::new(&self.buffer.as_ref()[20..]);
        let id = buf.read_u32::<BigEndian>()?;
        Ok(id)
    }

    pub fn ip_addr(&self) -> Result<(Ipv4Addr, Ipv6Addr)> {
        let buf = self.buffer.as_ref();
        let ipv4: [u8; 4] = buf[0..4].try_into().map_err(|_| Error::InvalidPacket)?;
        let ipv6: [u8; 16] = buf[4..20].try_into().map_err(|_| Error::InvalidPacket)?;

        Ok((ipv4.into(), ipv6.into()))
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
