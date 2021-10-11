use crate::cryptor::{Aes128Cryptor, Aes256Cryptor, Cryptor, Plain};
use md5::{Digest, Md5};

pub fn secret_to_key<T: AsRef<str>>(secret: T) -> [u8; 16] {
    let mut d = Md5::default();
    d.update(secret.as_ref().as_bytes());

    let key = d.finalize();
    *key.as_ref()
}

#[derive(Clone)]
pub enum Cipher {
    Plain,
    Aes128,
    Aes256,
}

#[derive(Clone)]
pub struct Builder {
    key: [u8; 16],
    cipher: Cipher,
}

impl Default for Builder {
    fn default() -> Self {
        Self {
            cipher: Cipher::Plain,
            key: [0u8; 16],
        }
    }
}

impl Builder {
    pub fn new<A: AsRef<str>, B: AsRef<str>>(
        secret: A,
        cipher: B,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let cipher = match cipher.as_ref() {
            "plain" => Cipher::Plain,
            "aes-128" => Cipher::Aes128,
            "aes-256" => Cipher::Aes256,
            _ => Err("invalid cipher")?,
        };

        Ok(Self {
            cipher: cipher,
            key: secret_to_key(secret),
        })
    }
    pub fn build(&self) -> Box<dyn Cryptor> {
        match self.cipher {
            Cipher::Plain => Box::new(Plain::new()),
            Cipher::Aes128 => Box::new(Aes128Cryptor::new(&self.key, 16)),
            Cipher::Aes256 => Box::new(Aes256Cryptor::new(&self.key, 32)),
        }
    }
}
