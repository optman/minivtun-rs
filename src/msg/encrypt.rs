use crate::cryptor::Cryptor;
use crate::error::Result;
use crate::msg::builder::PacketTransform;

pub struct Encryptor<'a> {
    cryptor: Option<&'a dyn Cryptor>,
}

impl<'a> Encryptor<'a> {
    pub fn new(cryptor: Option<&'a dyn Cryptor>) -> Self {
        Self { cryptor }
    }
}

impl PacketTransform for Encryptor<'_> {
    fn transform(&self, mut data: Vec<u8>) -> Result<Vec<u8>> {
        if let Some(cryptor) = self.cryptor {
            data[4..20].copy_from_slice(cryptor.auth_key());
            Ok(cryptor.encrypt_vec(&data)?)
        } else {
            Ok(data)
        }
    }
}
