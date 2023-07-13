package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/mpdroog/passdb/stream"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/term"
	"math/rand"
	"os"
	"strings"
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
	letters = []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()")

	// Lookup-table for all files in creds.d dir
	Lookup map[string]string
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

func parseFile(bytePassword []byte, fname string, out interface{}) error {
	fd, e := os.Open(fname)
	if e != nil {
		return e
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
		return e
	}
	if n != 8 {
		return fmt.Errorf("Reading nonce failed")
	}

	privKey, e := scryptKey(bytePassword, ([8]byte)(nonce))
	r, e := stream.NewReader(privKey, fd)
	if e != nil {
		return e
	}

	if e := json.NewDecoder(r).Decode(out); e != nil {
		return e
	}

	return nil
}

func writeFile(nonce []byte, privKey []byte, path string, f interface{}) error {
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
	s, e := reader.ReadString('\n')
	s = strings.TrimSpace(s)
	return s, e
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
		fmt.Printf("\t%s export gitlab\n", os.Args[0])
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

	// Lookup-tbl
	{
		fname := fmt.Sprintf("%s/lookup.json.enc", dbPath)
		haveFile := true
		if _, e := os.Stat(fname); errors.Is(e, os.ErrNotExist) {
			Lookup = make(map[string]string)
			haveFile = false
		}
		if e != nil {
			panic(e)
		}

		if haveFile {
			if e := parseFile(bytePassword, fname, &Lookup); e != nil {
				panic(e)
			}
		}
	}

	var fname string
	var hash string
	{
		h := sha256.New()
		h.Write([]byte(os.Args[2]))
		hash = fmt.Sprintf("%x", h.Sum(nil))
		fname = fmt.Sprintf("%s/%s.json.enc", dbPath, hash)
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

		if _, err := os.Stat(fname); err == nil {
			if e := parseFile(bytePassword, fname, &c); e != nil {
				panic(e)
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			// Only panic when error something else than nonexists
			panic(e)
		}

		c.Creds = append(c.Creds, Cred{User: user, Pass: pass, Meta: meta})
		if Verbose {
			fmt.Printf("Write=%+v\n", c)
		}

		nonce := randSeq(8)
		privKey, e := scryptKey(bytePassword, ([8]byte)(nonce))
		if e != nil {
			panic(e)
		}
		if e := writeFile(nonce, privKey, fname, &c); e != nil {
			panic(e)
		}

		// Now also update Lookup
		{
			nonce := randSeq(8)
			privKey, e := scryptKey(bytePassword, ([8]byte)(nonce))
			if e != nil {
				panic(e)
			}
			Lookup[os.Args[2]] = hash
			if e := writeFile(nonce, privKey, dbPath+"/lookup.json.enc", Lookup); e != nil {
				panic(e)
			}
		}

	} else if os.Args[1] == "export" {
		if Verbose {
			fmt.Printf("lookup=%+v\n", Lookup)
		}
		for name, fname := range Lookup {
			fullFname := fmt.Sprintf("%s/%s.json.enc", dbPath, fname)
			if Verbose {
				fmt.Printf("Read=%s (%s)\n", name, fullFname)
			}
			var creds = File{}
			if e := parseFile(bytePassword, fullFname, &creds); e != nil {
				panic(e)
			}
			for id, cred := range creds.Creds {
				fmt.Printf("User=%s\n", cred.User)
				fmt.Printf("Pass=%s\n", cred.Pass)
				fmt.Printf("Meta=%s\n", cred.Meta)
				if id+1 != len(creds.Creds) {
					fmt.Printf("\n")
				}
			}
		}

	} else if os.Args[1] == "get" {
		if Verbose {
			fmt.Printf("Read=%s\n", fname)
		}
		var creds = File{}
		if e := parseFile(bytePassword, fname, &creds); e != nil {
			panic(e)
		}
		for id, cred := range creds.Creds {
			fmt.Printf("User=%s\n", cred.User)
			fmt.Printf("Pass=%s\n", cred.Pass)
			fmt.Printf("Meta=%s\n", cred.Meta)
			if id+1 != len(creds.Creds) {
				fmt.Printf("\n")
			}
		}

	} else {
		fmt.Printf("Invalid args\n")
		os.Exit(1)
		return
	}
}
