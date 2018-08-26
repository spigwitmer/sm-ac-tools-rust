package main

import (
    "spigwitmer/smactools"
    "bytes"
    "flag"
    "io"
    "log"
    "os"
)

var (
    in_file string
    out_file string
)

func init() {
    flag.StringVar(&in_file, "i", "", "input file (required, \"-\" for stdin)")
    flag.StringVar(&out_file, "o", "dec.zip", "output file (\"-\" for stdout)")
}

func main() {
    flag.Parse()
    if in_file == "" {
        flag.Usage()
        os.Exit(2)
    }

    var f io.Reader
    var destf io.Writer
    var err error

    if in_file == "-" {
        f = os.Stdin
    } else {
        f, err = os.OpenFile(in_file, os.O_RDONLY, 0755)
        if err != nil {
            log.Fatalf("Could not open input file: %v\n", err)
        }
    }

    header := new(smactools.CryptHeader)
    err = header.ReadPatchHeaderFromFile(f)
    if err != nil {
        log.Fatalf("Could not read patch header: %v\n", err)
    }

    block, err := smactools.DeriveCipherKey(header.Subkey, []byte(smactools.ITG2SubkeySalt))
    if err != nil {
        log.Fatalf("Could not derive AES key: %v\n", err)
    }

    verify_scratchpad := make([]byte, 16)
    block.Decrypt(verify_scratchpad, header.VerifyBlock)
    log.Printf("verify magic: %v\n", verify_scratchpad[:2])
    if ! bytes.Equal(verify_scratchpad[:2], []byte(":D")) {
        log.Fatal("Bad verify magic")
    }

    if out_file == "-" {
        destf = os.Stdout
    } else {
        destf, err = os.OpenFile(out_file, os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0644)
        if err != nil {
            log.Fatalf("Could not open %s for writing: %v\n", out_file, err)
        }
    }

    log.Printf("Decrypting: %s -> %s\n", in_file, out_file)
    smactools.DecryptFile(f, destf, block)
}
