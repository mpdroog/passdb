package main

import (
	"errors"
	"flag"
	"fmt"
	"github.com/mpdroog/passdb/lib"
	"os"
	"strings"
)

func main() {
	flag.Parse()
	args := flag.Args()

	lib.DBPath = "../creds.d"

	cmd := args[0]
	fname := args[1]
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
			lib.Lookup = make(map[string]string)
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

	if cmd == "find" {
		for name, filename := range lib.Lookup {
			if !strings.Contains(name, fname) {
				// Keyname does not match
				continue
			}
			if lib.Verbose {
				fmt.Printf("Match %s => %s\n", name, filename)
			}
			var creds = lib.File{}
			fullFname := fmt.Sprintf("%s/%s.json.enc", lib.DBPath, filename)
			if e := lib.ParseFile(bytePassword, fullFname, &creds); e != nil {
				panic(e)
			}
			fmt.Printf("\n%s\n=======================\n", name)
			for id, cred := range creds.Creds {
				fmt.Printf("user: %s\n", cred.User)
				fmt.Printf("pass: %s\n", cred.Pass)
				fmt.Printf("meta: %s\n", cred.Meta)
				fmt.Printf("url: %s\n", cred.URL)
				if id+1 != len(creds.Creds) {
					fmt.Printf("\n")
				}
			}
		}

	} else {
		fmt.Printf("No such cmd=%s\n", cmd)
		os.Exit(1)
		return
	}
}
