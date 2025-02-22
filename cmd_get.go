package main

import (
	"crypto/sha256"
	"fmt"
	"github.com/mpdroog/passdb/lib"
)

func getCmd(fname, arg string) {
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
}
