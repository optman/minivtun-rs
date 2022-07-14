use crate::error::Error;

pub trait Cryptor {
    fn auth_key(&self) -> &[u8; 16];
    fn encrypt(&self, buffer: &[u8]) -> Result<Vec<u8>, Error>;
    fn decrypt(&self, buffer: &[u8]) -> Result<Vec<u8>, Error>;
}
