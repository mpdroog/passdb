package main

import (
	"fmt"
	"os"

	qrterminal "github.com/mdp/qrterminal/v3"
	"github.com/mpdroog/passdb/lib"
)

func loadCmd(fname, arg string) (bool, error) {
	fname = fmt.Sprintf("%s/%s.json.enc", lib.DBPath, fname)

	if Verbose {
		fmt.Printf("Read=%s\n", fname)
	}
	// TODO: Maybe suggest if file not exists?

	var creds = lib.File{}
	if e := lib.ParseFile(bytePassword, fname, &creds); e != nil {
		return false, e
	}
	for id, cred := range creds.Creds {
		fmt.Printf("user=%s\n", cred.User)
		if QR {
			qrterminal.Generate(cred.Pass, qrterminal.L, os.Stdout)
		} else {
			fmt.Printf("pass=%s\n", cred.Pass)
		}
		fmt.Printf("meta=%s\n", cred.Meta)
		fmt.Printf("url=%s\n", cred.URL)
		if id+1 != len(creds.Creds) {
			fmt.Printf("\n")
		}
	}

	return true, nil
}
