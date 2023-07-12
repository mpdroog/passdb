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
	"os"
	"syscall"
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
)

func scryptKey(pass []byte) ([]byte, error) {
	// DO NOT use this salt value; generate your own random salt. 8 bytes is
	// a good length.
	salt := []byte{0xc8, 0x28, 0xf2, 0x58, 0xa7, 0x6a, 0xad, 0x7b}

	return scrypt.Key(pass, salt, 1<<15, 8, 1, 32)
}

func parseFile(privKey []byte, fname string) (*File, error) {
	fd, e := os.Open(fname)
	if e != nil {
		return nil, e
	}
	defer func() {
		if e := fd.Close(); e != nil {
			fmt.Printf("parseFile.Close e=%s\n", e.Error())
		}
	}()

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

func writeFile(privKey []byte, path string, f *File) error {
	fd, e := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	defer func() {
		if e := fd.Close(); e != nil {
			fmt.Printf("writeFile.Close e=%s\n", e.Error())
		}
	}()

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
	dbPath := ""
	flag.BoolVar(&Verbose, "v", false, "Show all that happens")
	flag.StringVar(&dbPath, "d", "./creds.d", "Path to credentials-dir")
	flag.Parse()

	if len(os.Args) < 2 {
		fmt.Printf("Example usage:\n")
		fmt.Printf("\t%s search github\n", os.Args[0])
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
	var privKey []byte
	{
		bytePassword, e := term.ReadPassword(int(syscall.Stdin))
		if e != nil {
			panic(e)
		}
		privKey, e = scryptKey(bytePassword)
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
		if e := writeFile(privKey, fname, &c); e != nil {
			panic(e)
		}

	} else if os.Args[1] == "search" {
		fmt.Printf("Read=%s\n", fname)
		creds, e := parseFile(privKey, fname)
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
