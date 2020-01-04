package main

import (
	"fmt"
	"io"
	"os"
	"syscall"

	"golang.org/x/crypto/ssh/terminal"
)

func main() {
	if err := NewApp().Execute(); err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
}

func exitOnErr(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}
}

func promptPassword(message string, out io.Writer) ([]byte, error) {
	fmt.Fprintf(out, "Enter Password for '%s': ", message)
	pw, err := terminal.ReadPassword(int(syscall.Stdin))
	fmt.Println("")
	return pw, err
}
