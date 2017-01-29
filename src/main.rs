extern crate crypto;

mod constants;
mod patch_file;
mod crypt;

use std::fs::File;
use std::env;
use std::error::Error;
use std::io::stderr;
use std::io::Write;
use std::process::exit;
use patch_file::{CryptFileMetadata, extract_metadata};
use crypt::derive_aes_key;
use constants::FILE_MAGIC_ITG2;

fn usage(argv0: &str) {
    println!("Usage: {0} <source file> <dest file>", argv0);
}

#[cfg(not(test))]
fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 && args.len() > 0 {
        usage(&*args[0]);
        exit(2);
    }

    let src_file: &str = &args[1];
    //let dst_file: &str = &args[2];

    let mut crypt_metadata = CryptFileMetadata::new();
    let mut aes_key = [0; 24];
    let mut src_fhnd = match File::open(src_file) {
        Ok(hnd) => hnd,
        Err(e) => panic!("Could not open src file: {}", e.description())
    };
    match extract_metadata(&mut src_fhnd, &mut crypt_metadata) {
        Err(e) => panic!("Could not read crypt metadata: {}",
                         e.description()),
        Ok(_) => derive_aes_key(&crypt_metadata, &mut aes_key)
    }

    if crypt_metadata.magic[..] != FILE_MAGIC_ITG2[..] {
        writeln!(std::io::stderr(), "Error: bad file magic");
        exit(1);
    }

    println!("Magic: {}{}",
        crypt_metadata.magic[0] as char,
        crypt_metadata.magic[1] as char);
    println!("File Size: {}", crypt_metadata.file_size);
    println!("Subkey size: {}", crypt_metadata.subkey_size);
}
