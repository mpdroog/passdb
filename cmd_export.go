package main

import (
	"fmt"
	"github.com/mpdroog/passdb/lib"
)

func exportCmd(fname, arg string) (bool, error) {
	if Verbose {
		fmt.Printf("lookup=%+v\n", lib.Lookup)
	}

	for name, fname := range lib.Lookup {
		fullFname := fmt.Sprintf("%s/%s.json.enc", lib.DBPath, fname)
		fmt.Printf("\n%s\n=======================\n", name)
		var creds = lib.File{}
		if e := lib.ParseFile(bytePassword, fullFname, &creds); e != nil {
			fmt.Printf("ERR: File(%s) e=%s\n", fullFname, e.Error())
			continue
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

	return false, nil
}
