use crate::cryptor::{Aes128Cryptor, Aes256Cryptor, Cryptor};
use md5::{Digest, Md5};

/// Converts a secret string into a 16-byte key using MD5
pub fn secret_to_key<T: AsRef<str>>(secret: T) -> [u8; 16] {
    let mut d = Md5::default();
    d.update(secret.as_ref().as_bytes());
    let key = d.finalize();
    *key.as_ref()
}

/// Enum representing different cipher algorithms
#[derive(Clone)]
pub enum Cipher {
    Plain,
    Aes128,
    Aes256,
}

/// Builder for constructing cryptors
#[derive(Clone)]
pub struct Builder {
    key: [u8; 16],
    cipher: Cipher,
}

impl Default for Builder {
    fn default() -> Self {
        Self {
            cipher: Cipher::Plain,
            key: [0; 16],
        }
    }
}

impl Builder {
    /// Creates a new Builder instance with the provided secret and cipher type
    pub fn new<A: AsRef<str>, B: AsRef<str>>(
        secret: A,
        cipher: B,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let cipher = match cipher.as_ref().to_lowercase().as_str() {
            "plain" => Cipher::Plain,
            "aes-128" => Cipher::Aes128,
            "aes-256" => Cipher::Aes256,
            _ => Err("invalid cipher")?,
        };

        Ok(Self {
            cipher,
            key: secret_to_key(secret),
        })
    }

    /// Builds a cryptor based on the configured cipher type
    pub fn build(&self) -> Option<Box<dyn Cryptor>> {
        match self.cipher {
            Cipher::Plain => None,
            Cipher::Aes128 => Some(Box::new(Aes128Cryptor::new(&self.key))),
            Cipher::Aes256 => Some(Box::new(Aes256Cryptor::new(&self.key))),
        }
    }
}
