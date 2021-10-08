use crate::error::{Error, Result};
use ipnet::IpNet;
use std::convert::TryInto;
use std::net::IpAddr;
use std::process::Command;

fn ipv4_from_slice(s: &[u8]) -> Result<IpAddr> {
    let addr: [u8; 4] = s[..4].try_into().map_err(|_| Error::InvalidPacket)?;
    Ok(addr.into())
}

fn ipv6_from_slice(s: &[u8]) -> Result<IpAddr> {
    let addr: [u8; 16] = s[..16].try_into().map_err(|_| Error::InvalidPacket)?;
    Ok(addr.into())
}

pub fn source_ip(pkt: &[u8]) -> Result<IpAddr> {
    match pkt[0] >> 4 {
        4 => ipv4_from_slice(&pkt[12..]),
        6 => ipv6_from_slice(&pkt[8..]),
        _ => Err(Error::InvalidPacket),
    }
}

pub fn dest_ip(pkt: &[u8]) -> Result<IpAddr> {
    match pkt[0] >> 4 {
        4 => ipv4_from_slice(&pkt[16..]),
        6 => ipv6_from_slice(&pkt[24..]),
        _ => Err(Error::InvalidPacket),
    }
}

pub fn add_addr(addr: IpNet, dev: &str) -> Result<()> {
    let mut c = Command::new("ip");
    if let IpNet::V6(_) = addr {
        c.arg("-6");
    };

    if !c
        .arg("addr")
        .arg("add")
        .arg(addr.to_string())
        .arg("dev")
        .arg(dev)
        .status()
        .map_or(false, |c| c.success())
    {
        Err(Error::AddAddrFail)?
    }

    Ok(())
}

pub fn add_route(
    addr: &IpNet,
    dev: &str,
    table: &Option<String>,
    metric: &Option<String>,
) -> Result<()> {
    let mut c = Command::new("ip");
    if let IpNet::V6(_) = addr {
        c.arg("-6");
    };

    c.arg("route")
        .arg("add")
        .arg(addr.to_string())
        .arg("dev")
        .arg(dev);

    if let Some(table) = table {
        c.arg("table");
        c.arg(table);
    }

    if let Some(metric) = metric {
        c.arg("metric");
        c.arg(metric);
    }

    if c.status().map_or(false, |c| c.success()) {
        return Ok(());
    }

    Err(Error::AddRouteFail)?
}
