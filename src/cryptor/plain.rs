use crate::cryptor::Cryptor;
use crate::error::Error;

#[derive(Clone, Copy)]
pub struct Plain {}
impl Plain {
    pub fn new() -> Self {
        Self {}
    }
}

impl Cryptor for Plain {
    fn is_plain(&self) -> bool {
        true
    }
    fn auth_key(&self) -> &[u8; 16] {
        unimplemented!();
    }

    fn encrypt(&mut self, _buffer: &[u8]) -> Result<Vec<u8>, Error> {
        unimplemented!();
    }

    fn decrypt(&mut self, _buffer: &[u8]) -> Result<Vec<u8>, Error> {
        unimplemented!();
    }
}
