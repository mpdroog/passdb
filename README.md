Passdb
===================
Yet another password manager.
Small Go CLI-tool that asks for your master password and then decodes a small textfile with encrypted passwords you can easilly share across your computers.

Why create this?
- Got tired of vendor lock-ins and cloud B/S;
- Wanted something simple so I can easily share it between all of my machines;

```bash
./passdb add gitlab
user: mark
pass: 1234
meta:
Write={Creds:[{User:mark
 Pass:1234
 Meta:
}]}

./passdb get gitlab
Read=./creds.d/9d96d9d5b1addd7e7e6119a23b1e5b5f68545312bfecb21d1cdc6af22b8628b8.json.enc
&{[{mark
 1234

}]}
```

creds.d structure
==================
Store all credentials and lookup-table into one directory. This way
you can easilly send all your passwords everywhere you want with i.e. Git

```
creds.d
- lookup.json.enc contains map[file] = sha256(file)
- sha256file.json.enc contains chacha20poly1305(File) 
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