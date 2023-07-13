Passdb
===================
Yet another password manager.
Small Go CLI-tool that asks for your master password and then decodes a small textfile with encrypted passwords you can easilly share across your computers.

Why create this?
- Got tired of vendor lock-ins and cloud B/S;
- Wanted something simple so I can easily share it between all of my machines;

```bash
# Add new entry to DB with file github
./passdb add github
user: fourth
pass: four
meta: four

./passdb add github
user: one
pass: one
meta: one

# Get all entries for given file
./passdb get github
user=fourth
pass=four
meta=four

user=one
pass=one
meta=one

# Get all entries
./passdb export all
github
=======================
user=fourth
pass=four
meta=four

user=one
pass=one
meta=one
```

creds.d structure
==================
Store all credentials and lookup-table into one directory. This way
you can easilly send all your passwords everywhere you want with i.e. Git

```
creds.d
- lookup.json.enc contains chacha20poly1305(Lookup)
- sha256file.json.enc contains chacha20poly1305(File) 
```

lookup.json.enc
```go
Lookup map[string]string = map[fileName] = sha256(fileName)
```

sha256file.json.enc
```go
type File struct {
	Creds []Cred
}

type Cred struct {
	User string
	Pass string
	Meta string
}
```

