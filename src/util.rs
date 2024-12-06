use crate::error::{Error, Result};
use rand::Rng;
use std::{net::IpAddr, time::Duration};

/// Converts a byte slice to an IPv4 address
fn ipv4_from_slice(s: &[u8]) -> IpAddr {
    let mut addr = [0; 4];
    addr.copy_from_slice(&s[0..4]);
    addr.into()
}

/// Converts a byte slice to an IPv6 address
fn ipv6_from_slice(s: &[u8]) -> IpAddr {
    let mut addr = [0; 16];
    addr.copy_from_slice(&s[0..16]);
    addr.into()
}

/// Extracts the source IP from a packet
pub fn source_ip(pkt: &[u8]) -> Result<IpAddr> {
    match pkt[0] >> 4 {
        4 => Ok(ipv4_from_slice(&pkt[12..])),
        6 => Ok(ipv6_from_slice(&pkt[8..])),
        _ => Err(Error::InvalidPacket),
    }
}

/// Extracts the destination IP from a packet
pub fn dest_ip(pkt: &[u8]) -> Result<IpAddr> {
    match pkt[0] >> 4 {
        4 => Ok(ipv4_from_slice(&pkt[16..])),
        6 => Ok(ipv6_from_slice(&pkt[24..])),
        _ => Err(Error::InvalidPacket),
    }
}

/// Builds a server address by choosing a random port within a specified range
///
/// # Arguments
///
/// * `addr` - A string slice that holds the address in the form of "hostname:port-range"
///
/// # Returns
///
/// A `String` representing the full server address, with a randomly chosen port if a range is provided.
pub fn build_server_addr(addr: &str) -> String {
    let (host, port) = addr
        .rsplit_once(':')
        .expect("Address must be in the form 'hostname:port' or 'hostname:port-range'");

    let mut ports = port.split('-');
    let gen_addr = if let Some(start_port) = ports
        .next()
        .map(|v| v.parse::<u16>().expect("Invalid start port"))
    {
        if let Some(end_port) = ports
            .next()
            .map(|v| v.parse::<u16>().expect("Invalid end port"))
        {
            let port: u16 = rand::thread_rng().gen_range(start_port..end_port);
            Some(format!("{}:{}", host, port))
        } else {
            None
        }
    } else {
        None
    };

    gen_addr.unwrap_or_else(|| addr.to_owned())
}
pub(crate) fn pretty_duration(duration: &Duration) -> String {
    pretty_duration::pretty_duration(&Duration::from_secs(duration.as_secs()), None)
}
