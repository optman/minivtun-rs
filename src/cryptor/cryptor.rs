use crate::error::Error;

pub trait Cryptor {
    fn is_plain(&self) -> bool;
    fn auth_key(&self) -> &[u8; 16];
    fn encrypt(&mut self, buffer: &[u8]) -> Result<Vec<u8>, Error>;
    fn decrypt(&mut self, buffer: &[u8]) -> Result<Vec<u8>, Error>;
}
