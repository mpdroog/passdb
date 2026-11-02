package lib

import (
	"bufio"
	"fmt"
	"golang.org/x/term"
	"os"
	"os/signal"
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
// The terminal state is restored when a signal (i.e. CTRL+C) aborts the prompt,
// otherwise the shell is left without echo.
func GetPass(question string) ([]byte, error) {
	fmt.Print(question + ": ")

	state, e := term.GetState(syscall.Stdin)
	if e != nil {
		return nil, e
	}

	sig := make(chan os.Signal, 1)
	done := make(chan struct{})
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sig)
	defer close(done)

	go func() {
		select {
		case s := <-sig:
			fmt.Println()
			if e := term.Restore(syscall.Stdin, state); e != nil {
				fmt.Printf("Failed restoring terminal (run: stty sane), e=%s\n", e.Error())
			}
			// Shell convention, exit with 128+signal
			code := 1
			if n, ok := s.(syscall.Signal); ok {
				code = 128 + int(n)
			}
			os.Exit(code)
		case <-done:
		}
	}()

	return term.ReadPassword(syscall.Stdin)
}
