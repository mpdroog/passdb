package main

import (
	"flag"
	"fmt"
	"github.com/inancgumus/screen"
	"github.com/mpdroog/passdb/lib"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type CmdFunc func(string, string) (bool, error)

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
		"load":     loadCmd,
	}
)

func showHelp() {
	usage := `Passdb.
  Password manager that optimises for easily distributing your passwords.

Usage:
  passdb find <name> [-v] [-d=<dir>]
  passdb get <name> [-v] [-d=<dir>]
  passdb load <hash> [-v] [-d=<dir>]
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
	name := args[1]

	var e error
	bytePassword, e = lib.GetPass()
	if e != nil {
		fmt.Printf("Failed reading pass\n")
		os.Exit(1)
	}
	fmt.Printf("\n")

	// Lookup 2.0, dynamically create it
	lib.Lookup = make(map[string]string)
	e = filepath.WalkDir(lib.DBPath, func(s string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}

		fname, _ := strings.CutSuffix(d.Name(), ".json.enc")
		lib.Lookup[fname] = fname
		return nil
	})
	if e != nil {
		fmt.Printf("Failed creating dynamic index, e=%s\n", e.Error())
		os.Exit(1)
	}

	// TODO: only sleep if true by fn?
	clear, e := fn(name, cmd)
	if e != nil {
		fmt.Printf("ERR %s\n", e.Error())
		os.Exit(1)
		return
	}

	if clear {
	}
	if false {
		//fmt.Printf(">> Sleep 10sec >> clear screen\n")
		time.Sleep(10 * time.Second)
		screen.Clear()
	}
}
