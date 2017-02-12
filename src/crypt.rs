use std::io;
use std::io::prelude::*;
use std::result;
use std::cmp;
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
        .map_err(|_: SymmetricCipherError| {
            "Cipher error during verification"
        })
        .and_then(|_: BufferResult| {
            let mut dreadbuf = dec_buf.take_read_buffer();
            let dmagic = dreadbuf.take_remaining();
            print!("dmagic: ");
            let dmagic_iter = dmagic.into_iter();
            for x in dmagic_iter {
                print!("{0:x} ", x);
            }
            println!("");
            Ok(dmagic[0..2] == DECRYPT_MAGIC_ITG2[0..2])
        });
    res
}

pub fn decrypt_file<T: Read, U: Write>(metadata: &CryptFileMetadata,
                                       aes_key: &[u8; 24],
                                       src: &mut T,
                                       dst: &mut U)
                                      -> Result<usize, &'static str> {
    let mut decryptor = aes::ecb_decryptor(
            aes::KeySize::KeySize192,
            &aes_key[..],
            blockmodes::NoPadding);
    let mut prev_block = [0u8; 16];
    let mut cur_block = [0u8; 16];
    let mut cur_cipher = [0u8; 16];
    let mut cur_buf = RefWriteBuffer::new(&mut cur_block);
    let mut total_bytes: usize = 0;
    let mut last_read_count: usize = 0;
    let mut bytes_written: usize = 0;

    /*
     * Decrypt in blocks of 16 bytes.
     * XOR the current decrypted block with the previous block.
     * Null out the previous block every 4080 bytes.
     */
    loop {
        try!(src.read(&mut cur_cipher)
            .or_else(|err: io::Error| {
                Err("I/O error during read")
            })
            .and_then(|read_count: usize| {
                last_read_count = read_count;
                total_bytes += read_count;
                let mut cipher_buf = RefReadBuffer::new(&mut cur_cipher);
                decryptor.decrypt(&mut cipher_buf, &mut cur_buf, true)
                .or_else(|_: SymmetricCipherError| {
                    Err("Cipher error during decryption")
                })
                .and_then(|_: BufferResult| {
                    let mut cur_buf_read_buffer = cur_buf.take_read_buffer();
                    let mut dec_block: &[u8] = cur_buf_read_buffer.take_next(16);
                    for i in 0..16 {
                        //cur_block[i] ^= prev_block[i] - i as u8;
                        prev_block[i] = (dec_block[i] ^ prev_block[i]) - i as u8;
                    }
                    // TODO: 4080 check
                    bytes_written = cmp::min(
                            cmp::min(16, last_read_count),
                            metadata.file_size as usize - total_bytes
                            );
                    dst.write_all(&prev_block[0..bytes_written])
                    .or_else(|r: io::Error| {
                        Err("Write error")
                    })
                })
            }));
        if bytes_written < 16 {
            break;
        }
    }
    Ok(metadata.file_size as usize)
}
