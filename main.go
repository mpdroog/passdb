package main

import (
	"errors"
	"flag"
	"fmt"
	"github.com/mpdroog/passdb/lib"
	"os"
)

type CmdFunc func(string, string)

var (
	Help         bool
	Verbose      bool
	letters      = []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()")
	bytePassword []byte
	validCmds    = map[string]CmdFunc{
		"find":     findCmd,
		"get":      getCmd,
		"add":      addCmd,
		"set":      addCmd,
		"import":   importCmd,
		"export":   exportCmd,
		"generate": generateCmd,
	}
)

func showHelp() {
	usage := `Passdb.
  Password manager that optimises for easily distributing your passwords.

Usage:
  passdb find <name> [-v] [-d=<dir>]
  passdb get <name> [-v] [-d=<dir>]
  passdb add <name> [-v] [-d=<dir>]
  passdb set <name> [-v] [-d=<dir>]
  passdb generate <name> [-v] [-d=<dir>]
  passdb import <file> [-v] [-d=<dir>]
  passdb export all [-v] [-d=<dir>]
  passdb -h

Options:
  -h                  Show this screen.
  -v                  Verbose mode.
  -d=<dir>            Credentials-dir [default: ./creds.d].`

	fmt.Println(usage)
}

func main() {
	flag.StringVar(&lib.DBPath, "d", "./creds.d", "Credentials-dir")
	flag.BoolVar(&Verbose, "v", false, "Verbose-mode (log more)")
	flag.BoolVar(&Help, "h", false, "Show this screen")

	flag.Usage = showHelp
	flag.Parse()
	args := flag.Args()

	if Verbose {
		fmt.Printf("args=%+v\n", args)
	}
	if Help {
		flag.Usage()
		os.Exit(0)
	}

	if len(args) >= 2 {
		if _, ok := validCmds[args[0]]; !ok {
			if _, ok := validCmds[args[1]]; ok {
				// Weird OS, strip off one (i.e. terminal on Android)
				args = args[1:]
			}
		}
	}

	if len(args) < 2 {
		flag.Usage()
		os.Exit(1)
	}

	fn, found := validCmds[args[0]]
	if !found {
		fmt.Printf("Invalid cmd=%s\n", args[0])
		flag.Usage()
		os.Exit(1)
	}
	cmd := args[0]
	fname := args[1]

	var e error
	bytePassword, e = lib.GetPass()
	if e != nil {
		fmt.Printf("Failed reading pass\n")
		os.Exit(1)
	}

	// Lookup-tbl
	{
		fname := fmt.Sprintf("%s/lookup.json.enc", lib.DBPath)
		haveFile := true
		_, e := os.Stat(fname)
		if errors.Is(e, os.ErrNotExist) {
			lib.Lookup = make(map[string]string)
			haveFile = false
		} else if e != nil {
			fmt.Printf("ERR: %s\n", e.Error())
			os.Exit(1)
			return
		}

		if !haveFile {
			fmt.Printf("ERR: Missing lookup.json.enc\n")
			os.Exit(1)
			return
		}

		if haveFile {
			e := lib.ParseFile(bytePassword, fname, &lib.Lookup)
			fmt.Printf("\n") // newline
			if e != nil {
				if e.Error() == "failed to decrypt and authenticate payload chunk" {
					fmt.Printf("ERR: Invalid master password\n")
					os.Exit(1)
					return
				}
				panic(e)
			}
		}
		if Verbose {
			fmt.Printf("Lookup=%d entries\n", len(lib.Lookup))
		}
	}

	fn(fname, cmd)
}
