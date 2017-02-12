use std::io;
use std::io::prelude::*;

pub struct CryptFileMetadata {
    pub magic: [u8; 2],
    pub file_size: u32,
    pub subkey_size: u32,
    pub subkey: Vec<u8>,
    pub verify_block: [u8; 16]
}

impl CryptFileMetadata {
    pub fn new() -> CryptFileMetadata {
        CryptFileMetadata {
            magic: [0, 0],
            file_size: 0,
            subkey_size: 0,
            subkey: vec![0u8],
            verify_block: [0; 16]
        }
    }
}

pub fn read_u32_le<T: Read> (fhnd: &mut T) -> io::Result<u32> {
    let mut buf: [u8; 4] = [0; 4];
    try!(fhnd.read_exact(&mut buf));

    Ok(buf[0] as u32 + 
        ((buf[1] as u32) << 8) + 
        ((buf[2] as u32) << 16) +
        ((buf[3] as u32) << 24))
}

pub fn extract_metadata<T: Read>(fhnd: &mut T,
                                 metadata: &mut CryptFileMetadata)
                                -> io::Result<i32> {
    try!(fhnd.read_exact(&mut metadata.magic));
    metadata.file_size = try!(read_u32_le(fhnd));
    metadata.subkey_size = try!(read_u32_le(fhnd));
    metadata.subkey = Vec::with_capacity(metadata.subkey_size as usize);
    try!(fhnd.read_exact(&mut metadata.subkey[..]));
    try!(fhnd.read_exact(&mut metadata.verify_block));
    Ok(0)
}

#[cfg(test)]
mod test {
    use patch_file::read_u32_le;

    #[test]
    fn test_read_little_endian() {
        let mut fakeio = &[0xe1u8, 0x07, 0, 0] as &[u8];
        let le_val = read_u32_le(&mut fakeio);
        assert!(le_val.is_ok());
        assert_eq!(le_val.unwrap(), 2017);
    }
}
