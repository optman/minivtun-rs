use crate::cryptor::Cryptor;
use crate::error::Error;
use aes::{Aes128, Aes256};
use block_modes::block_padding::{PadError, UnpadError};
use block_modes::{
    block_padding::Padding, cipher::BlockCipher, cipher::NewBlockCipher, BlockMode, Cbc,
};
use std::marker::PhantomData;

// ZeroPadding code is copied from block_modes::block_padding::ZeroPadding
// to modify the unpad() method.
//
// Enum representing zero-padding for block ciphers
#[derive(Clone, Copy, Debug)]
pub enum ZeroPadding {}

/// Sets the provided slice with the given value
#[inline(always)]
fn set(dst: &mut [u8], value: u8) {
    unsafe {
        core::ptr::write_bytes(dst.as_mut_ptr(), value, dst.len());
    }
}

impl Padding for ZeroPadding {
    fn pad_block(block: &mut [u8], pos: usize) -> Result<(), PadError> {
        if pos > block.len() {
            return Err(PadError);
        }
        set(&mut block[pos..], 0);
        Ok(())
    }

    fn pad(buf: &mut [u8], pos: usize, block_size: usize) -> Result<&mut [u8], PadError> {
        if pos.is_multiple_of(block_size) {
            Ok(&mut buf[..pos])
        } else {
            let bs = block_size * (pos / block_size);
            let be = bs + block_size;
            if buf.len() < be {
                return Err(PadError);
            }
            Self::pad_block(&mut buf[bs..be], pos - bs)?;
            Ok(&mut buf[..be])
        }
    }

    fn unpad(data: &[u8]) -> Result<&[u8], UnpadError> {
        Ok(data)
    }
}

pub type Aes128Cryptor = AesCryptor<Aes128, ZeroPadding, Cbc<Aes128, ZeroPadding>, 16>;
pub type Aes256Cryptor = AesCryptor<Aes256, ZeroPadding, Cbc<Aes256, ZeroPadding>, 32>;

/// Initial vector for encryption
const IV: [u8; 32] = [
    0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90,
    0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90,
];

/// Structure representing an AES cryptor with a specific padding and block mode
#[derive(Clone, Copy)]
pub struct AesCryptor<C, P, T, const KEY_SIZE: usize> {
    auth_key: [u8; 16],
    key: [u8; KEY_SIZE],
    _marker: PhantomData<C>,
    _marker2: PhantomData<P>,
    _marker3: PhantomData<T>,
}

impl<C, P, T, const KEY_SIZE: usize> AesCryptor<C, P, T, KEY_SIZE> {
    /// Creates a new instance of AesCryptor
    pub fn new(auth_key: &[u8; 16]) -> Self {
        let mut a = Self {
            auth_key: *auth_key,
            key: [0; KEY_SIZE],
            _marker: PhantomData,
            _marker2: PhantomData,
            _marker3: PhantomData,
        };

        for i in 0..KEY_SIZE / 16 {
            a.key[i * 16..(i + 1) * 16].copy_from_slice(auth_key);
        }

        a
    }
}

impl<C, P, T, const KEY_SIZE: usize> Cryptor for AesCryptor<C, P, T, KEY_SIZE>
where
    C: BlockCipher + NewBlockCipher,
    P: Padding,
    T: BlockMode<C, P>,
{
    fn auth_key(&self) -> &[u8; 16] {
        &self.auth_key
    }

    fn encrypt<'a>(&self, buffer: &'a mut [u8], pos: usize) -> Result<&'a [u8], Error> {
        let cipher =
            T::new_from_slices(&self.key[..KEY_SIZE], &IV[..16]).map_err(|_| Error::EncryptFail)?;

        cipher.encrypt(buffer, pos).map_err(|_| Error::EncryptFail)
    }

    fn decrypt<'a>(&self, buffer: &'a mut [u8]) -> Result<&'a [u8], Error> {
        let cipher =
            T::new_from_slices(&self.key[..KEY_SIZE], &IV[..16]).map_err(|_| Error::EncryptFail)?;

        cipher.decrypt(buffer).map_err(|_| Error::DecryptFail)
    }

    fn encrypt_vec(&self, buffer: &[u8]) -> Result<Vec<u8>, Error> {
        let cipher =
            T::new_from_slices(&self.key[..KEY_SIZE], &IV[..16]).map_err(|_| Error::EncryptFail)?;

        Ok(cipher.encrypt_vec(buffer))
    }

    fn decrypt_vec(&self, buffer: &[u8]) -> Result<Vec<u8>, Error> {
        let cipher =
            T::new_from_slices(&self.key[..KEY_SIZE], &IV[..16]).map_err(|_| Error::EncryptFail)?;

        cipher.decrypt_vec(buffer).map_err(|_| Error::DecryptFail)
    }
}

#[cfg(test)]
mod tests {
    use self::super::*;
    use std::convert::TryInto;
    
    #[test]
    fn tests() {
        let key: Vec<u8> = std::iter::repeat_n(1, 16).collect();
        let key: [u8; 16] = key.try_into().unwrap();
        let data: Vec<u8> = std::iter::repeat_n(2, 64).collect();

        let c = Aes128Cryptor::new(&key);

        let cipher_txt = c.encrypt_vec(&data).unwrap();

        let plain_txt = c.decrypt_vec(&cipher_txt).unwrap();

        assert_eq!(data, plain_txt);
    }
}
