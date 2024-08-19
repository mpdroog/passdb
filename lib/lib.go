package lib

var (
	DBPath  string
	Verbose bool
	letters = []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()")

	// Lookup-table for all files in creds.d dir
	Lookup map[string]string
)
