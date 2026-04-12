package lib

import (
	"bufio"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/mpdroog/passdb/stream"
	"golang.org/x/crypto/scrypt"
	"os"
)

// File is the base struct for every file
type File struct {
	Creds []Cred
}

// Cred contains one entry in the file
type Cred struct {
	User string
	Pass string
	Meta string
	Type string
	URL  string
}

// RandSeq creates a byte array of N-items drawn from the letters alphabet
// using a cryptographically secure random source.
func RandSeq(n int) []byte {
	b := make([]byte, n)
	if _, e := rand.Read(b); e != nil {
		panic(e)
	}
	for i := range b {
		b[i] = letters[int(b[i])%len(letters)]
	}
	return b
}

// scryptKey generates a password with random nonce for better security of file
func ScryptKey(bytePassword []byte, nonce [8]byte) ([]byte, error) {
	// devnote: using [8]byte to enforce fixed length
	return scrypt.Key(bytePassword, nonce[:], 1<<15, 8, 1, 32)
}

// parseFile reads the creds-dir with given pass
func ParseFile(bytePassword []byte, fname string, out interface{}) error {
	fd, e := os.Open(fname) //nolint:gosec // caller is responsible for sanitizing fname
	if e != nil {
		return e
	}
	defer func() {
		if e := fd.Close(); e != nil {
			fmt.Printf("parseFile.Close e=%s\n", e.Error())
		}
	}()

	r := bufio.NewReader(fd)

	// Read nonce from first 8 bytes
	nonce := make([]byte, 8)
	n, e := r.Read(nonce)
	if e != nil {
		return e
	}
	if n != 8 {
		return fmt.Errorf("reading nonce failed")
	}

	privKey, e := ScryptKey(bytePassword, ([8]byte)(nonce))
	if e != nil {
		return e
	}
	rs, e := stream.NewReader(privKey, r)
	if e != nil {
		return e
	}

	if e := json.NewDecoder(rs).Decode(out); e != nil {
		return e
	}

	return nil
}

// writeFile stores encrypted(json(f-var)) in given path
func WriteFile(nonce []byte, privKey []byte, path string, f interface{}) error {
	fd, e := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600) //nolint:gosec // caller is responsible for sanitizing path
	if e != nil {
		return e
	}
	defer func() {
		if e := fd.Close(); e != nil {
			fmt.Printf("writeFile.Close e=%s\n", e.Error())
		}
	}()

	w := bufio.NewWriter(fd)

	n, e := w.Write(nonce)
	if e != nil {
		return e
	}
	if n != 8 {
		return fmt.Errorf("failed writing nonce")
	}

	sw, e := stream.NewWriter(privKey, w)
	if e != nil {
		return e
	}
	defer func() {
		if e := w.Flush(); e != nil {
			fmt.Printf("writeFile.Flush e=%s\n", e.Error())
		}
		if e := sw.Close(); e != nil {
			fmt.Printf("writeFile.StreamClose e=%s\n", e.Error())
		}
	}()

	if e := json.NewEncoder(sw).Encode(f); e != nil {
		return e
	}
	return nil
}

// add wraps the writeFile-func by offering an overwrite-option
func Add(name string, bytePassword []byte, cred Cred, overwrite bool) error {
	fname := fmt.Sprintf("%s/%s.json.enc", DBPath, name)
	c := File{}

	if _, e := os.Stat(fname); e == nil {
		if e := ParseFile(bytePassword, fname, &c); e != nil {
			return e
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		// Only panic when error something else than nonexists
		return e
	}

	var delCreds []Cred
	if overwrite {
		delCreds = append(delCreds, c.Creds...)
		c = File{}
	}
	c.Creds = append(c.Creds, cred)

	if Verbose {
		fmt.Printf("Write=%v to %s\n", c, fname)
	}

	nonce := RandSeq(8)
	privKey, e := ScryptKey(bytePassword, ([8]byte)(nonce))
	if e != nil {
		return e
	}
	if e := WriteFile(nonce, privKey, fname, &c); e != nil {
		return e
	}
	for _, oldCred := range delCreds {
		fmt.Printf("Deleted %v\n", oldCred)
	}

	return nil
}
