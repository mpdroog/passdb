package main

import (
	"crypto/sha256"
	"encoding/csv"
	"errors"
	"fmt"
	"github.com/docopt/docopt-go"
	"github.com/mpdroog/passdb/lib"
	"io"
	"os"
	"strings"
)

var (
	Verbose bool
	letters = []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()")

	// Lookup-table for all files in creds.d dir
	Lookup map[string]string
)

func main() {
	usage := `Passdb.
  Password manager that optimises for easily distributing your passwords.

Usage:
  passdb find <name> [--verbose] [--dir=<dir>]
  passdb get <name> [--verbose] [--dir=<dir>]
  passdb add <name> [--verbose] [--dir=<dir>]
  passdb set <name> [--verbose] [--dir=<dir>]
  passdb generate <name> [--verbose] [--dir=<dir>]
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
	lib.DBPath, e = args.String("--dir")
	if e != nil {
		panic(e)
	}

	cmd := ""
	// TODO: Kind of duplicate
	for _, k := range []string{"find", "get", "add", "set", "import", "export", "generate"} {
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

	bytePassword, e := lib.GetPass()
	if e != nil {
		panic(e)
	}
	fmt.Println() // newline after passfield

	// Lookup-tbl
	{
		fname := fmt.Sprintf("%s/lookup.json.enc", lib.DBPath)
		haveFile := true
		_, e := os.Stat(fname)
		if errors.Is(e, os.ErrNotExist) {
			Lookup = make(map[string]string)
			haveFile = false
		} else if e != nil {
			panic(e)
		}

		if haveFile {
			if e := lib.ParseFile(bytePassword, fname, &lib.Lookup); e != nil {
				panic(e)
			}
		}
	}

	if cmd == "add" || cmd == "set" {
		user, e := lib.GetStdin("user")
		if e != nil {
			panic(e)
		}
		// TODO: Hide pass from shell?
		pass, e := lib.GetStdin("pass")
		if e != nil {
			panic(e)
		}
		meta, e := lib.GetStdin("meta")
		if e != nil {
			panic(e)
		}

		overwrite := false
		if cmd == "set" {
			overwrite = true
		}
		lib.Add(fname, bytePassword, lib.Cred{User: user, Pass: pass, Meta: meta}, overwrite)

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
			c := lib.Cred{User: toks[4], Pass: toks[0], Meta: toks[1], URL: toks[3], Type: toks[2]}
			if Verbose {
				fmt.Printf("C(key=%s)=%+v\n", key, c)
			}
			lib.Add(key, bytePassword, c, false)
		}

	} else if cmd == "export" {
		if Verbose {
			fmt.Printf("lookup=%+v\n", Lookup)
		}
		for name, fname := range Lookup {
			fullFname := fmt.Sprintf("%s/%s.json.enc", lib.DBPath, fname)
			fmt.Printf("\n%s\n=======================\n", name)
			var creds = lib.File{}
			if e := lib.ParseFile(bytePassword, fullFname, &creds); e != nil {
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
			var creds = lib.File{}
			fullFname := fmt.Sprintf("%s/%s.json.enc", lib.DBPath, filename)
			if e := lib.ParseFile(bytePassword, fullFname, &creds); e != nil {
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
			fname = fmt.Sprintf("%s/%s.json.enc", lib.DBPath, hash)
		}

		if Verbose {
			fmt.Printf("Read=%s\n", fname)
		}
		// TODO: Maybe suggest if file not exists?

		var creds = lib.File{}
		if e := lib.ParseFile(bytePassword, fname, &creds); e != nil {
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
	} else if cmd == "generate" {
		var pass []byte
		for {
			// Random pass
			pass = lib.RandSeq(12)
			fmt.Printf("pass=%s\n", pass)
			ok := ""
			ok, e := lib.GetStdin("confirm to save (y)")
			if e != nil {
				panic(e)
			}
			if ok == "y" {
				break
			}
		}

		user, e := lib.GetStdin("user")
		if e != nil {
			panic(e)
		}
		meta, e := lib.GetStdin("meta")
		if e != nil {
			panic(e)
		}

		var hash string
		{
			h := sha256.New()
			h.Write([]byte(fname))
			hash = fmt.Sprintf("%x", h.Sum(nil))
			fname = fmt.Sprintf("%s/%s.json.enc", lib.DBPath, hash)
		}

		fmt.Printf("user=%s\n", user)
		fmt.Printf("pass=%s\n", pass)
		fmt.Printf("meta=%s\n", meta)

		if _, e := lib.GetStdin("confirm to save"); e != nil {
			panic(e)
		}

		lib.Add(fname, bytePassword, lib.Cred{User: user, Pass: string(pass), Meta: meta}, false)

	} else {
		fmt.Printf("No such cmd=%s\n", cmd)
		os.Exit(1)
		return
	}
}
