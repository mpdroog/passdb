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

./passdb search gitlab
Read=./creds.d/9d96d9d5b1addd7e7e6119a23b1e5b5f68545312bfecb21d1cdc6af22b8628b8.json.enc
&{[{mark
 1234

}]}
```