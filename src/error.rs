use std::fmt;
use std::result;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    InvalidArg(String),
    InvalidPacket,
    EncryptFail,
    DecryptFail,
    AddAddrFail,
    AddRouteFail,
    NoRoute(String),
    IoError(#[from] std::io::Error),
    PacketError(#[from] packet::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", *self)
    }
}

pub type Result<T> = result::Result<T, Error>;
