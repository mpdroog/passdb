package main

import (
	"errors"
	"flag"
	"fmt"
	"github.com/mpdroog/passdb/lib"
	"os"
)

var (
	Help         bool
	Verbose      bool
	letters      = []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()")
	bytePassword []byte
)

func showHelp() {
	usage := `Passdb.
  Password manager that optimises for easily distributing your passwords.

Usage:
  passdb find <name> [--verbose] [--dir=<dir>]
  passdb get <name> [--verbose] [--dir=<dir>]
  passdb add <name> [--verbose] [--dir=<dir>]
  passdb set <name> [--verbose] [--dir=<dir>]
  passdb generate <name> [--verbose] [--dir=<dir>]
  passdb import <file> [--verbose] [--dir=<dir>]
  passdb export all [--verbose] [--dir=<dir>]
  passdb -h | --help

Options:
  -h --help           Show this screen.
  -v --verbose        Verbose mode.
  -d --dir=<dir>      Credentials-dir [default: ./creds.d].`

	fmt.Println(usage)
}

type CmdFunc func(string, string)

func main() {
	flag.StringVar(&lib.DBPath, "d", "./creds.d", "Credentials-dir")
	flag.BoolVar(&Verbose, "v", false, "Verbose-mode (log more)")
	flag.BoolVar(&Help, "h", false, "Show this screen")

	flag.Parse()
	args := flag.Args()

	if Verbose {
		fmt.Println(args)
	}
	if Help {
		showHelp()
		os.Exit(0)
		return
	}

	// TODO: Function pointer..
	validCmds := map[string]CmdFunc{
		"find":     findCmd,
		"get":      getCmd,
		"add":      addCmd,
		"set":      addCmd,
		"import":   importCmd,
		"export":   exportCmd,
		"generate": generateCmd,
	}
	if len(args) < 2 {
		showHelp()
		os.Exit(1)
		return
	}

	fn, found := validCmds[args[0]]
	if !found {
		fmt.Printf("Invalid cmd=%s\n", args[0])
		showHelp()
		os.Exit(1)
		return
	}
	cmd := args[0]
	fname := args[1]

	var e error
	bytePassword, e = lib.GetPass()
	if e != nil {
		fmt.Printf("Failed reading pass\n")
		os.Exit(1)
		return
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
