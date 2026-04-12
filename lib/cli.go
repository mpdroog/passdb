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

// GetPass asks for a password with echo disabled so typed characters are hidden.
func GetPass(question string) ([]byte, error) {
	fmt.Print(question + ": ")
	return term.ReadPassword(int(syscall.Stdin))
}
