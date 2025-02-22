package main

import (
	"github.com/mpdroog/passdb/lib"
)

func addCmd(fname, cmd string) {
	user, e := lib.GetStdin("user")
	if e != nil {
		panic(e)
	}
	// TODO: Hide pass from shell?
	pass, e := lib.GetStdin("pass")
	if e != nil {
		panic(e)
	}
	meta, e := lib.GetStdin("meta")
	if e != nil {
		panic(e)
	}

	overwrite := false
	if cmd == "set" {
		overwrite = true
	}
	lib.Add(fname, bytePassword, lib.Cred{User: user, Pass: pass, Meta: meta}, overwrite)
}
