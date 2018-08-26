package smactools

import (
    "io"
    "encoding/binary"
    "fmt"
    "bytes"
)

type CryptHeader struct {
    Magic []byte
    FileSize uint32
    SubkeyLength uint32
    Subkey []byte
    VerifyBlock []byte
}

func (c *CryptHeader) ReadPatchHeaderFromFile(f io.Reader) error {
    /* Expect the file to start with "8O" */
    c.Magic = make([]byte, 2)
    _, err := f.Read(c.Magic)
    if err != nil {
        return err
    }
    if ! bytes.Equal(c.Magic, []byte("8O")) {
        return fmt.Errorf("Bad file magic: %v", c.Magic)
    }

    /* Size of decrypted file */
    err = binary.Read(f, binary.LittleEndian, &c.FileSize)
    if err != nil {
        return err
    }

    /* Length of the subkey */
    err = binary.Read(f, binary.LittleEndian, &c.SubkeyLength)
    if err != nil {
        return err
    }

    c.Subkey = make([]byte, c.SubkeyLength)
    _, err = io.ReadFull(f, c.Subkey)
    if err != nil {
        return err
    }

    c.VerifyBlock = make([]byte, 16)
    _, err = io.ReadFull(f, c.VerifyBlock)
    return err
}
