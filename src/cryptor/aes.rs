use crate::cryptor::Cryptor;
use crate::error::Error;
use aes::{Aes128, Aes256};
use block_modes::block_padding::{PadError, UnpadError};
use block_modes::{
    block_padding::Padding, cipher::BlockCipher, cipher::NewBlockCipher, BlockMode, Cbc,
};
use std::marker::PhantomData;

//ZeroPadding code is copy from block_modes::block_padding::ZeroPadding
//to modify uppad() method.
//
#[derive(Clone, Copy, Debug)]
pub enum ZeroPadding {}

#[inline(always)]
fn set(dst: &mut [u8], value: u8) {
    unsafe {
        core::ptr::write_bytes(dst.as_mut_ptr(), value, dst.len());
    }
}

impl Padding for ZeroPadding {
    fn pad_block(block: &mut [u8], pos: usize) -> Result<(), PadError> {
        if pos > block.len() {
            Err(PadError)?
        }
        set(&mut block[pos..], 0);
        Ok(())
    }

    fn pad(buf: &mut [u8], pos: usize, block_size: usize) -> Result<&mut [u8], PadError> {
        if pos % block_size == 0 {
            Ok(&mut buf[..pos])
        } else {
            let bs = block_size * (pos / block_size);
            let be = bs + block_size;
            if buf.len() < be {
                Err(PadError)?
            }
            Self::pad_block(&mut buf[bs..be], pos - bs)?;
            Ok(&mut buf[..be])
        }
    }

    fn unpad(data: &[u8]) -> Result<&[u8], UnpadError> {
        Ok(data)
    }
}

pub type Aes128Cryptor = AesCryptor<Aes128, ZeroPadding, Cbc<Aes128, ZeroPadding>>;
pub type Aes256Cryptor = AesCryptor<Aes256, ZeroPadding, Cbc<Aes256, ZeroPadding>>;

const IV: [u8; 32] = [
    0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90,
    0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90,
];

#[derive(Clone, Copy)]
pub struct AesCryptor<C, P, T> {
    auth_key: [u8; 16],
    key: [u8; 32],
    key_size: usize,
    _marker: PhantomData<C>,
    _marker2: PhantomData<P>,
    _marker3: PhantomData<T>,
}

impl<C, P, T> AesCryptor<C, P, T> {
    pub fn new(auth_key: &[u8; 16], key_size: usize) -> Self {
        let mut a = Self {
            auth_key: *auth_key,
            key: [0u8; 32],
            key_size: key_size,
            _marker: PhantomData,
            _marker2: PhantomData,
            _marker3: PhantomData,
        };

        a.key[0..16].copy_from_slice(auth_key);
        a.key[16..32].copy_from_slice(auth_key);

        a
    }
}

impl<C, P, T> Cryptor for AesCryptor<C, P, T>
where
    C: BlockCipher + NewBlockCipher,
    P: Padding,
    T: BlockMode<C, P>,
{
    fn is_plain(&self) -> bool {
        false
    }

    fn auth_key(&self) -> &[u8; 16] {
        &self.auth_key
    }

    fn encrypt(&mut self, buffer: &[u8]) -> Result<Vec<u8>, Error> {
        let cipher = T::new_from_slices(&self.key[..self.key_size], &IV[..16])
            .map_err(|_| Error::EncryptFail)?;

        Ok(cipher.encrypt_vec(buffer))
    }

    fn decrypt(&mut self, buffer: &[u8]) -> Result<Vec<u8>, Error> {
        let cipher = T::new_from_slices(&self.key[..self.key_size], &IV[..16])
            .map_err(|_| Error::EncryptFail)?;

        Ok(cipher.decrypt_vec(buffer).map_err(|_| Error::DecryptFail)?)
    }
}

#[cfg(test)]
mod tests {
    use self::super::*;
    use std::convert::TryInto;
    use std::iter::repeat;

    #[test]
    fn tests() {
        let key: Vec<u8> = repeat(1).take(16).collect();
        let key: [u8; 16] = key.try_into().unwrap();
        let data: Vec<u8> = repeat(2).take(64).collect();

        let mut c = Aes128Cryptor::new(&key, 16);

        let cipher_txt = c.encrypt(&data).unwrap();

        let plain_txt = c.decrypt(&cipher_txt).unwrap();

        assert_eq!(data, plain_txt);
    }
}
