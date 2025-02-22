package main

import (
	"fmt"
	"github.com/mpdroog/passdb/lib"
	"strings"
)

func findCmd(fname, arg string) {
	for name, filename := range lib.Lookup {
		if !strings.Contains(name, fname) {
			if Verbose {
				fmt.Printf("Mismatch %s => %s\n", name, filename)
			}
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
			fmt.Printf("user: %s\n", cred.User)
			fmt.Printf("pass: %s\n", cred.Pass)
			fmt.Printf("meta: %s\n", cred.Meta)
			fmt.Printf("url: %s\n", cred.URL)
			if id+1 != len(creds.Creds) {
				fmt.Printf("\n")
			}
		}
	}
}
