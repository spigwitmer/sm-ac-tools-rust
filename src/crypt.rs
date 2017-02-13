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
                                      -> Result<usize, String> {
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

    /*
     * Decrypt in blocks of 16 bytes.
     * XOR the current decrypted block with the previous block.
     * Null out the previous block every 4080 bytes.
     */
    loop {
        let bytes_written: usize = try!(src.read(&mut cur_cipher)
            .or_else(|er: io::Error| {
                Err(format!("I/O error during read: {0}", er))
            })
            .and_then(|read_count: usize| {
                if read_count == 0 {
                    return Ok(0)
                }
                last_read_count = read_count;
                total_bytes += read_count;
                let mut cipher_buf = RefReadBuffer::new(&mut cur_cipher);

                let mut decrypt_res = Ok(BufferResult::BufferUnderflow);
                loop {
                    decrypt_res = decryptor.decrypt(&mut cipher_buf, &mut cur_buf, true);
                    match decrypt_res {
                        /* We shouldn't be hitting BoFs when doing 16 bytes at a time.. */
                        Ok(BufferResult::BufferOverflow) =>
                            return Err(String::from("Buffer overflow")),
                        Ok(BufferResult::BufferUnderflow) =>
                            break,
                        Err(_) => { }
                    }
                }

                decrypt_res
                .or_else(|er: SymmetricCipherError| {
                    Err(format!("Cipher error during decryption: {0:?}", er))
                })
                .and_then(|_: BufferResult| {
                    let mut cur_buf_read_buffer = cur_buf.take_read_buffer();
                    let dec_block: &[u8] = cur_buf_read_buffer.take_remaining();
                    if dec_block.len() == 0 {
                        println!("Empty decryption block?");
                        return Ok(0)
                    }
                    if total_bytes % 4080 == 0 {
                        prev_block = [0u8; 16];
                    }
                    for i in 0..16 {
                        prev_block[i] = dec_block[i] ^
                                        prev_block[i].wrapping_sub(i as u8);
                    }
                    // TODO: 4080 check
                    println!("file_size, total_bytes, last_read_count: {0} {1} {2}",
                             metadata.file_size, total_bytes, last_read_count);
                    let to_write: usize = cmp::min(metadata.file_size as usize,
                                                   last_read_count);
                    dst.write_all(&prev_block[0..to_write])
                    .or_else(|er: io::Error| {
                        Err(format!("Write error: {0}", er))
                    })
                    .and_then(|_: _| {
                        Ok(to_write)
                    })
                })
            }));
        println!("bytes_written: {0}", bytes_written);
        if bytes_written < 16 {
            break;
        }
    }
    Ok(metadata.file_size as usize)
}
