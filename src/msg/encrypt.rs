use crate::cryptor::Cryptor;
use crate::error::Result;
use crate::msg::builder::Finalizer;
use packet::Buffer;

pub struct Encryptor<'a>(Option<&'a dyn Cryptor>);

impl<'a> Encryptor<'a> {
    pub fn new(cryptor: Option<&'a dyn Cryptor>) -> Self {
        Self(cryptor)
    }
}

impl<B: Buffer> Finalizer<B> for Encryptor<'_> {
    fn finalize(&self, data: B) -> Result<Vec<u8>> {
        if let Some(cryptor) = self.0 {
            let mut data = data.into_inner();
            data.as_mut()[4..20].copy_from_slice(cryptor.auth_key());
            Ok(cryptor.encrypt_vec(data.as_mut())?)
        } else {
            Ok(data.into_inner().as_mut().to_owned())
        }
    }
}

pub const NO_ENCRYPT: Encryptor<'static> = Encryptor(None);
