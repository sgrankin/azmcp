package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 || len(os.Args) > 3 || os.Args[1] != "--worker" || len(os.Args) == 3 && os.Args[2] != "--sync" {
		fmt.Fprintln(os.Stderr, "usage: azmcp-quickjs-worker --worker [--sync]")
		os.Exit(2)
	}
	if err := runWorkerMode(os.Stdin, os.Stdout, len(os.Args) == 3); err != nil {
		fmt.Fprintln(os.Stderr, sanitize(err.Error(), maxErrorBytes))
		os.Exit(1)
	}
}
