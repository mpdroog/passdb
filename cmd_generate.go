package main

import (
	"crypto/sha256"
	"fmt"
	"github.com/mpdroog/passdb/lib"
)

func generateCmd(fname, arg string) (bool, error) {
	var pass []byte
	for {
		// Random pass
		pass = lib.RandSeq(12)
		fmt.Printf("pass=%s\n", pass)
		ok := ""
		ok, e := lib.GetStdin("confirm to save (y)")
		if e != nil {
			return false, e
		}
		if ok == "y" {
			break
		}
	}

	user, e := lib.GetStdin("user")
	if e != nil {
		return false, e
	}
	meta, e := lib.GetStdin("meta")
	if e != nil {
		return false, e
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
		return false, e
	}

	lib.Add(fname, bytePassword, lib.Cred{User: user, Pass: string(pass), Meta: meta}, false)
	return true, nil
}
