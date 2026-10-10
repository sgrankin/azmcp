package main

import (
	"azmcp/internal/server"
	"azmcp/internal/worker"
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

func run() error {
	args := os.Args[1:]
	if len(args) == 1 && args[0] == "--worker" {
		return worker.RunWorker(os.Stdin, os.Stdout)
	}
	if len(args) != 0 {
		return fmt.Errorf("usage: azmcp [--worker]")
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	runtime, err := server.Production(executable)
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
