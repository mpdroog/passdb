package main

import (
	"encoding/csv"
	"fmt"
	"github.com/mpdroog/passdb/lib"
	"io"
	"os"
	"strings"
)

func importCmd(fname, arg string) (bool, error) {
	// 1Password CSV format
	// Login = "xyz","cointracker.io","Login","cointracker.io","mail@domain.com",
	// Wireless Router = "passss","Networkname","Wireless Router",,,
	// Bank Account = "1234","Bank Business","Bank Account",,,
	// Password = "xxx","eBay","Password","ebay.com",,
	if Verbose {
		fmt.Printf("import=%s\n", fname)
	}
	fd, e := os.Open(fname)
	if e != nil {
		return false, e
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
			return false, e
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

	return false, nil
}
