package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/mpdroog/passdb/stream"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/term"
	"math/rand"
	"os"
	"syscall"
	"time"
)

type File struct {
	Creds []Cred
}

type Cred struct {
	User string
	Pass string
	Meta string
}

var (
	Verbose bool
	letters = []byte("abcdefghijklmnopqrstuvwxyz")
)

func randSeq(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return b
}

func scryptKey(bytePassword []byte, nonce [8]byte) ([]byte, error) {
	// devnote: using [8]byte to enforce fixed length
	return scrypt.Key(bytePassword, nonce[:], 1<<15, 8, 1, 32)
}

func parseFile(bytePassword []byte, fname string) (*File, error) {
	fd, e := os.Open(fname)
	if e != nil {
		return nil, e
	}
	defer func() {
		if e := fd.Close(); e != nil {
			fmt.Printf("parseFile.Close e=%s\n", e.Error())
		}
	}()

	// Read nonce from first 8 bytes
	nonce := make([]byte, 8)
	n, e := fd.Read(nonce)
	if e != nil {
		return nil, e
	}
	if n != 8 {
		return nil, fmt.Errorf("Reading nonce failed")
	}

	privKey, e := scryptKey(bytePassword, ([8]byte)(nonce))
	r, e := stream.NewReader(privKey, fd)
	if e != nil {
		return nil, e
	}

	f := new(File)
	if e := json.NewDecoder(r).Decode(f); e != nil {
		return nil, e
	}

	return f, nil
}

func writeFile(nonce []byte, privKey []byte, path string, f *File) error {
	fd, e := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	defer func() {
		if e := fd.Close(); e != nil {
			fmt.Printf("writeFile.Close e=%s\n", e.Error())
		}
	}()

	n, e := fd.Write(nonce)
	if e != nil {
		return e
	}
	if n != 8 {
		return fmt.Errorf("Failed writing nonce")
	}

	w, e := stream.NewWriter(privKey, fd)
	if e != nil {
		return e
	}
	defer func() {
		if e := w.Close(); e != nil {
			fmt.Printf("writeFile.Close2 e=%s\n", e.Error())
		}
	}()

	if e := json.NewEncoder(w).Encode(f); e != nil {
		return e
	}
	return nil
}

func getStdin(question string) (string, error) {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print(question + ": ")
	return reader.ReadString('\n')
}

func main() {
	rand.Seed(time.Now().UnixNano())
	dbPath := ""
	flag.BoolVar(&Verbose, "v", false, "Show all that happens")
	flag.StringVar(&dbPath, "d", "./creds.d", "Path to credentials-dir")
	flag.Parse()

	if len(os.Args) < 2 {
		fmt.Printf("Example usage:\n")
		fmt.Printf("\t%s get github\n", os.Args[0])
		fmt.Printf("\t%s add gitlab\n", os.Args[0])
		os.Exit(1)
		return
	}

	file, e := os.Open(dbPath)
	if e != nil {
		panic(e)
	}
	defer file.Close()

	// TODO: protect privKey in memory?
	var bytePassword []byte
	{
		var e error
		bytePassword, e = term.ReadPassword(int(syscall.Stdin))
		if e != nil {
			panic(e)
		}
	}

	var fname string
	{
		h := sha256.New()
		h.Write([]byte(os.Args[2]))
		fname = fmt.Sprintf("%s/%x.json.enc", dbPath, h.Sum(nil))
	}

	if os.Args[1] == "add" {
		c := File{}

		user, e := getStdin("user")
		if e != nil {
			panic(e)
		}
		pass, e := getStdin("pass")
		if e != nil {
			panic(e)
		}
		meta, e := getStdin("meta")
		if e != nil {
			panic(e)
		}

		c.Creds = []Cred{
			Cred{User: user, Pass: pass, Meta: meta},
		}
		fmt.Printf("Write=%+v\n", c)

		nonce := randSeq(8)
		privKey, e := scryptKey(bytePassword, ([8]byte)(nonce))
		if e != nil {
			panic(e)
		}
		if e := writeFile(nonce, privKey, fname, &c); e != nil {
			panic(e)
		}
	} else if os.Args[1] == "search" {
		// Scan in all files?

	} else if os.Args[1] == "get" {
		fmt.Printf("Read=%s\n", fname)
		creds, e := parseFile(bytePassword, fname)
		if e != nil {
			panic(e)
		}
		fmt.Printf("%+s\n", creds)

	} else {
		fmt.Printf("Invalid args\n")
		os.Exit(1)
		return
	}
}
