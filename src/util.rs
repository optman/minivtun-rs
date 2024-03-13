use crate::error::{Error, Result};
use rand::Rng;
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

pub fn build_server_addr(addr: &str) -> String {
    let (host, port) = addr.rsplit_once(':').unwrap();

    let mut ports = port.split('-');
    let gen_addr = if let Some(start_port) = ports.next().map(|v| v.parse::<u16>().unwrap()) {
        if let Some(end_port) = ports.next().map(|v| v.parse::<u16>().unwrap()) {
            let port: u16 = rand::thread_rng().gen_range(start_port, end_port);
            Some(format!("{:}:{:}", host, port))
        } else {
            None
        }
    } else {
        None
    };

    gen_addr.unwrap_or(addr.to_owned())
}
