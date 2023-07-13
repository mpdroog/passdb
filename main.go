package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/docopt/docopt-go"
	"github.com/mpdroog/passdb/stream"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/term"
	"io"
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
	Type string
	URL  string
}

var (
	DBPath  string
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

	r := bufio.NewReader(fd)

	// Read nonce from first 8 bytes
	nonce := make([]byte, 8)
	n, e := r.Read(nonce)
	if e != nil {
		return e
	}
	if n != 8 {
		return fmt.Errorf("Reading nonce failed")
	}

	privKey, e := scryptKey(bytePassword, ([8]byte)(nonce))
	rs, e := stream.NewReader(privKey, r)
	if e != nil {
		return e
	}

	if e := json.NewDecoder(rs).Decode(out); e != nil {
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

	w := bufio.NewWriter(fd)

	n, e := w.Write(nonce)
	if e != nil {
		return e
	}
	if n != 8 {
		return fmt.Errorf("Failed writing nonce")
	}

	sw, e := stream.NewWriter(privKey, w)
	if e != nil {
		return e
	}
	defer func() {
		if e := sw.Close(); e != nil {
			fmt.Printf("writeFile.Close2 e=%s\n", e.Error())
		}
		if e := w.Flush(); e != nil {
                        fmt.Printf("writeFile.Flush e=%s\n", e.Error())
		}
	}()

	if e := json.NewEncoder(sw).Encode(f); e != nil {
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

func add(name string, bytePassword []byte, cred Cred, overwrite bool) {
	var hname string
	{
		h := sha256.New()
		h.Write([]byte(name))
		hname = fmt.Sprintf("%x", h.Sum(nil))
	}

	fname := fmt.Sprintf("%s/%s.json.enc", DBPath, hname)
	c := File{}

	if _, e := os.Stat(fname); e == nil {
		if e := parseFile(bytePassword, fname, &c); e != nil {
			panic(e)
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		// Only panic when error something else than nonexists
		panic(e)
	}

	if overwrite {
		c.Creds = []Cred{cred}
	} else {
		c.Creds = append(c.Creds, cred)
	}
	if Verbose {
		fmt.Printf("Write=%+v to %s\n", c, fname)
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
		Lookup[name] = hname
		if e := writeFile(nonce, privKey, DBPath+"/lookup.json.enc", Lookup); e != nil {
			panic(e)
		}
	}
}

func main() {
	rand.Seed(time.Now().UnixNano())
	usage := `Passdb.
  Password manager that optimises for easily distributing your passwords.

Usage:
  passdb find <name> [--verbose] [--dir=<dir>]
  passdb get <name> [--verbose] [--dir=<dir>]
  passdb add <name> [--verbose] [--dir=<dir>]
  passdb set <name> [--verbose] [--dir=<dir>]
  passdb import <file> [--verbose] [--dir=<dir>]
  passdb export [--verbose] [--dir=<dir>]
  passdb -h | --help

Options:
  -h --help           Show this screen.
  -v --verbose        Verbose mode.
  -d --dir=<dir>      Credentials-dir [default: ./creds.d].`

	args, e := docopt.ParseDoc(usage)
	if e != nil {
		panic(e)
	}
	Verbose, e = args.Bool("--verbose")
	if e != nil {
		panic(e)
	}
	if Verbose {
		fmt.Println(args)
	}
	DBPath, e = args.String("--dir")
	if e != nil {
		panic(e)
	}

	cmd := ""
	// TODO: Kind of duplicate
	for _, k := range []string{"find", "get", "add", "set", "import", "export"} {
		if ok, _ := args.Bool(k); ok {
			cmd = k
			break
		}
	}
	fname, _ := args.String("<name>")
	if len(fname) == 0 {
		// Kind of lazy
		fname, _ = args.String("<file>")
	}
	fname = strings.ToLower(fname)

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
		fname := fmt.Sprintf("%s/lookup.json.enc", DBPath)
		haveFile := true
		_, e := os.Stat(fname)
		if errors.Is(e, os.ErrNotExist) {
			Lookup = make(map[string]string)
			haveFile = false
		} else if e != nil {
			panic(e)
		}

		if haveFile {
			if e := parseFile(bytePassword, fname, &Lookup); e != nil {
				panic(e)
			}
		}
	}

	if cmd == "add" || cmd == "set" {
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

		overwrite := false
		if cmd == "set" {
			overwrite = true
		}
		add(fname, bytePassword, Cred{User: user, Pass: pass, Meta: meta}, overwrite)

	} else if cmd == "import" {
		// Login = "xyz","cointracker.io","Login","cointracker.io","mail@domain.com",
		// Wireless Router = "passss","Networkname","Wireless Router",,,
		// Bank Account = "1234","Bank Business","Bank Account",,,
		// Password = "xxx","eBay","Password","ebay.com",,
		if Verbose {
			fmt.Printf("import=%s\n", fname)
		}
		fd, e := os.Open(fname)
		if e != nil {
			panic(e)
		}
		defer fd.Close()

		// TODO: Cache file through bufferreader?
		r := csv.NewReader(fd)

		scanner := bufio.NewScanner(fd)
		// optionally, resize scanner's capacity for lines over 64K, see next example
		for {
			toks, e := r.Read()
			if e == io.EOF {
				break
			}
			if e != nil {
				panic(e)
			}
			if Verbose {
				fmt.Printf("%+v\n", toks)
			}

			key := strings.ReplaceAll(strings.ToLower(toks[1]), " ", "_")
			c := Cred{User: toks[4], Pass: toks[0], Meta: toks[1], URL: toks[3], Type: toks[2]}
			if Verbose {
				fmt.Printf("C(key=%s)=%+v\n", key, c)
			}
			add(key, bytePassword, c, false)
		}

		if e := scanner.Err(); e != nil {
			panic(e)
		}

	} else if cmd == "export" {
		if Verbose {
			fmt.Printf("lookup=%+v\n", Lookup)
		}
		for name, fname := range Lookup {
			fullFname := fmt.Sprintf("%s/%s.json.enc", DBPath, fname)
			fmt.Printf("\n%s\n=======================\n", name)
			var creds = File{}
			if e := parseFile(bytePassword, fullFname, &creds); e != nil {
				panic(e)
			}
			for id, cred := range creds.Creds {
				fmt.Printf("user=%s\n", cred.User)
				fmt.Printf("pass=%s\n", cred.Pass)
				fmt.Printf("meta=%s\n", cred.Meta)
				fmt.Printf("url=%s\n", cred.URL)
				if id+1 != len(creds.Creds) {
					fmt.Printf("\n")
				}
			}
		}

	} else if cmd == "find" {
		for name, filename := range Lookup {
			if !strings.Contains(name, fname) {
				// Keyname does not match
				continue
			}
			if Verbose {
				fmt.Printf("Match %s => %s\n", name, filename)
			}
			var creds = File{}
			fullFname := fmt.Sprintf("%s/%s.json.enc", DBPath, filename)
			if e := parseFile(bytePassword, fullFname, &creds); e != nil {
				panic(e)
			}
			fmt.Printf("\n%s\n=======================\n", name)
			for id, cred := range creds.Creds {
				fmt.Printf("user=%s\n", cred.User)
				fmt.Printf("pass=%s\n", cred.Pass)
				fmt.Printf("meta=%s\n", cred.Meta)
				fmt.Printf("url=%s\n", cred.URL)
				if id+1 != len(creds.Creds) {
					fmt.Printf("\n")
				}
			}
		}

	} else if cmd == "get" {
		var hash string
		{
			h := sha256.New()
			h.Write([]byte(fname))
			hash = fmt.Sprintf("%x", h.Sum(nil))
			fname = fmt.Sprintf("%s/%s.json.enc", DBPath, hash)
		}

		if Verbose {
			fmt.Printf("Read=%s\n", fname)
		}
		// TODO: Maybe suggest if file not exists?

		var creds = File{}
		if e := parseFile(bytePassword, fname, &creds); e != nil {
			panic(e)
		}
		for id, cred := range creds.Creds {
			fmt.Printf("user=%s\n", cred.User)
			fmt.Printf("pass=%s\n", cred.Pass)
			fmt.Printf("meta=%s\n", cred.Meta)
			fmt.Printf("url=%s\n", cred.URL)
			if id+1 != len(creds.Creds) {
				fmt.Printf("\n")
			}
		}

	} else {
		fmt.Printf("No such cmd=%s\n", cmd)
		os.Exit(1)
		return
	}
}
