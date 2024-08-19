package lib

import (
	"bufio"
	"fmt"
	"golang.org/x/term"
	"os"
	"strings"
	"syscall"
)

// getStdin asks question and returns the user reply
func GetStdin(question string) (string, error) {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print(question + ": ")
	s, e := reader.ReadString('\n')
	s = strings.TrimSpace(s)
	return s, e
}

// getPass asks for a password (same as getStdin except we don't show what user enters in CLI)
func GetPass() ([]byte, error) {
	fmt.Print("Master Pass: ")
	return term.ReadPassword(int(syscall.Stdin))
}
