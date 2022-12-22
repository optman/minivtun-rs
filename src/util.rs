use crate::error::{Error, Result};
use std::net::IpAddr;

#[inline]
fn ipv4_from_slice(s: &[u8]) -> IpAddr {
    let mut addr = [0; 4];
    addr.copy_from_slice(&s[0..4]);
    addr.into()
}

#[inline]
fn ipv6_from_slice(s: &[u8]) -> IpAddr {
    let mut addr = [0; 16];
    addr.copy_from_slice(&s[0..16]);
    addr.into()
}

#[inline]
pub fn source_ip(pkt: &[u8]) -> Result<IpAddr> {
    match pkt[0] >> 4 {
        4 => Ok(ipv4_from_slice(&pkt[12..])),
        6 => Ok(ipv6_from_slice(&pkt[8..])),
        _ => Err(Error::InvalidPacket),
    }
}

#[inline]
pub fn dest_ip(pkt: &[u8]) -> Result<IpAddr> {
    match pkt[0] >> 4 {
        4 => Ok(ipv4_from_slice(&pkt[16..])),
        6 => Ok(ipv6_from_slice(&pkt[24..])),
        _ => Err(Error::InvalidPacket),
    }
}
