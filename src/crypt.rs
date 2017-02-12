use std::io;
use std::io::prelude::*;
use std::result;
use std::fmt;
use crypto::digest::Digest;
use crypto::sha2::Sha512;
use crypto::aes;
use crypto::blockmodes;
use crypto::symmetriccipher::SymmetricCipherError;
use crypto::buffer::{ReadBuffer, WriteBuffer, BufferResult, RefReadBuffer, RefWriteBuffer};

use patch_file::CryptFileMetadata;
use constants::{PATCH_SALT_ITG2, DECRYPT_MAGIC_ITG2};

pub fn derive_aes_key(metadata: &CryptFileMetadata,
                      output: &mut [u8; 24]) {
    let mut sh = Sha512::new();
    sh.input(&metadata.subkey);
    sh.input(&PATCH_SALT_ITG2);
    {
        let mut ws = [0u8; 64];
        sh.result(&mut ws);
        output.copy_from_slice(&ws[0..24]);
    }
}

pub fn verify_crypt_metadata(metadata: &CryptFileMetadata,
                             aes_key: &[u8; 24])
                            -> result::Result<bool, &'static str> {
    let mut decryptor = aes::ecb_decryptor(
            aes::KeySize::KeySize192,
            &aes_key[..],
            blockmodes::NoPadding);
    let mut dec_block = [0u8; 16];
    let mut verify_block = RefReadBuffer::new(&metadata.verify_block[..]);
    let mut dec_buf = RefWriteBuffer::new(&mut dec_block[..]);
    let res = decryptor.decrypt(&mut verify_block,
                                &mut dec_buf,
                                true)
        .map(|r: BufferResult| {
            r
        })
        .map_err(|ex: SymmetricCipherError| {
            "Decrypt error"
        })
        .and_then(|r: BufferResult| {
            let mut dreadbuf = dec_buf.take_read_buffer();
            let mut dmagic = dreadbuf.take_remaining();
            Ok(dmagic[0..2] == DECRYPT_MAGIC_ITG2[0..2])
        });
    res
}

pub fn decrypt_file<T: Read, U: Write>(metadata: &CryptFileMetadata,
                                       aes_key: &[u8; 24],
                                       src: &mut T,
                                       dst: &mut U)
                                      -> io::Result<u32> {
    Ok(metadata.file_size)
}
