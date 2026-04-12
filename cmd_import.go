package main

import (
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/mpdroog/passdb/lib"
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
	fd, e := os.Open(fname) //nolint:gosec // caller-supplied import file path is intentional
	if e != nil {
		return false, e
	}
	defer func() {
		if e := fd.Close(); e != nil {
			fmt.Printf("importCmd.Close e=%s\n", e.Error())
		}
	}()

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

		if len(toks) < 5 {
			fmt.Printf("SKIP: row has %d columns, need 5: %+v\n", len(toks), toks)
			continue
		}
		key := strings.ReplaceAll(strings.ToLower(toks[1]), " ", "_")
		key = filepath.Base(filepath.Clean(key))
		if key == "." || key == "/" || strings.ContainsRune(key, os.PathSeparator) {
			fmt.Printf("SKIP: invalid key %q\n", toks[1])
			continue
		}
		c := lib.Cred{User: toks[4], Pass: toks[0], Meta: toks[1], URL: toks[3], Type: toks[2]}
		if Verbose {
			fmt.Printf("C(key=%s)=%+v\n", key, c)
		}
		if e := lib.Add(key, bytePassword, c, false); e != nil {
			return false, e
		}
	}

	return false, nil
}
