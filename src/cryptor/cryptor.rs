use crate::error::Error;

pub trait Cryptor {
    fn auth_key(&self) -> &[u8; 16];
    fn encrypt<'a>(&self, buffer: &'a mut [u8], pos: usize) -> Result<&'a [u8], Error>;
    fn decrypt<'a>(&self, buffer: &'a mut [u8]) -> Result<&'a [u8], Error>;
    fn encrypt_vec(&self, buffer: &[u8]) -> Result<Vec<u8>, Error>;
    fn decrypt_vec(&self, buffer: &[u8]) -> Result<Vec<u8>, Error>;
}
