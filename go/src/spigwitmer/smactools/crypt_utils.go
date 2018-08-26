package smactools

import (
    "crypto/sha512"
    "crypto/aes"
    "crypto/cipher"
    "errors"
    "log"
    "io"
)

func DeriveCipherKey(subkey []byte, subkey_salt []byte) (cipher.Block, error) {
    var err error = nil
    if subkey == nil {
        subkey, err = GetSubkeyFromDS1963S()
    }
    if err != nil {
        return nil, err
    }
    subkey_hash := sha512.New()
    log.Printf("Writing %d bytes for subkey\n", len(subkey))
    subkey_hash.Write(subkey)
    log.Printf("Writing %d bytes for subkey_salt\n", len(subkey_salt))
    subkey_hash.Write(subkey_salt)
    hash_key := subkey_hash.Sum(nil)[0:24]
    return aes.NewCipher(hash_key)
}

func GetSubkeyFromDS1963S() ([]byte, error) {
    /* not implemented */
    return nil, errors.New("dongle connected to boxor became loose or however that meme went")
}

func DecryptFile(src io.Reader, dest io.Writer, block cipher.Block) error {
    total_bytes_read := 0
    bytes_read := -1
    last_block := [16]byte{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}
    scratch_block := make([]byte, 16)
    dec_block := make([]byte, 16)
    var err error = nil

    /* Some hybrid of ECB and CBC */
    for err != io.EOF {
        bytes_read, err = src.Read(scratch_block)
        if bytes_read == 0 || err == io.EOF {
            continue
        }
        if err != nil {
            log.Fatalf("Bad things happened when decrypting: %v", err)
        }
        block.Decrypt(dec_block, scratch_block)
        for i, _ := range scratch_block {
            dec_block[i] = uint8(dec_block[i]) ^ (uint8(last_block[i]) - uint8(i))
            last_block[i] = scratch_block[i]
        }
        dest.Write(dec_block)
        total_bytes_read += bytes_read
        if total_bytes_read % 4080 == 0 {
            last_block = [16]byte{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}
        }
    }
    if err != io.EOF {
        return nil
    } else {
        return err
    }
}
