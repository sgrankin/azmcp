package main

import (
	"azmcp/internal/server"
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

func run() error {
	if len(os.Args) != 1 {
		return fmt.Errorf("usage: azmcp")
	}
	runtime, err := server.Production()
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	err = server.Serve(ctx, os.Stdin, os.Stdout, runtime.Application)
	return errors.Join(err, runtime.Close())
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "azmcp:", err)
		os.Exit(1)
	}
}
