package main

import (
	"fmt"
	"os"
	"strings"

	qrterminal "github.com/mdp/qrterminal/v3"
	"github.com/mpdroog/passdb/lib"
)

func findCmd(search, arg string) (bool, error) {
	if search == "" {
		return false, fmt.Errorf("search term cannot be empty")
	}
	m := false

	for name, _ := range lib.Lookup {
		is_match := strings.Contains(name, search)
		if !is_match {
			if false {
				fmt.Printf("Mismatch (%s != %s)\n", search, name)
			}
			// Keyname does not match
			continue
		}
		if Verbose {
			fmt.Printf("Filematch %s\n", name)
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
			if QR {
				qrterminal.Generate(cred.Pass, qrterminal.L, os.Stdout)
			} else {
				fmt.Printf("pass: %s\n", cred.Pass)
			}
			fmt.Printf("meta: %s\n", cred.Meta)
			fmt.Printf("url: %s\n", cred.URL)
			if id+1 != len(creds.Creds) {
				fmt.Printf("\n")
			}
		}
	}

	return m, nil
}
