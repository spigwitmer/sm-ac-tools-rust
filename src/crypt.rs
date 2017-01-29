use std::io;
use std::io::prelude::*;
use crypto::digest::Digest;
use crypto::sha2::Sha512;

use patch_file::CryptFileMetadata;
use constants::PATCH_SALT_ITG2;

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

pub fn verify_crypt_metadata(metadata: &CryptFileMetadata) -> bool {
    return true;
}

pub fn decrypt_file<T: Read, U: Write>(metadata: &CryptFileMetadata,
                             aes_key: &[u8; 24],
                             src: &mut T,
                             dst: &mut U)
                            -> io::Result<u32> {
    Ok(metadata.file_size)
}
