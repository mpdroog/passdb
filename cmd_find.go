package main

import (
	"fmt"
	"github.com/mpdroog/passdb/lib"
	"strings"
)

func findCmd(search, arg string) (bool, error) {
	m := false

	for name, _ := range lib.Lookup {
		is_match := strings.Contains(name, search)
		if !is_match {
			if Verbose {
				fmt.Printf("Mismatch (%s != %s)\n", search, name)
			}
			// Keyname does not match
			continue
		}
		if Verbose {
			fmt.Printf("Contains (%s == %s)\n", search, name)
		}

		var creds = lib.File{}
		fullFname := fmt.Sprintf("%s/%s.json.enc", lib.DBPath, name)
		if e := lib.ParseFile(bytePassword, fullFname, &creds); e != nil {
			return false, e
		}

		fmt.Printf("\n%s\n=======================\n", name)
		for id, cred := range creds.Creds {
			// match, showing passwords so use timer and clear screen
			m = true

			fmt.Printf("user: %s\n", cred.User)
			fmt.Printf("pass: %s\n", cred.Pass)
			fmt.Printf("meta: %s\n", cred.Meta)
			fmt.Printf("url: %s\n", cred.URL)
			if id+1 != len(creds.Creds) {
				fmt.Printf("\n")
			}
		}
	}

	return m, nil
}
