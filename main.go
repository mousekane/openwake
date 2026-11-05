package main

import (
	"fmt"
	"os"
)

func main() {
	loadConfig()
	if err := prepareTLS(); err != nil {
		fmt.Fprintln(os.Stderr, "tls error:", err)
		os.Exit(1)
	}
	go statusLoop()
	go ddnsLoop()
	go func() {
		if err := servePublic(); err != nil {
			fmt.Fprintln(os.Stderr, "public server error:", err)
			os.Exit(1)
		}
	}()
	if err := serve(); err != nil {
		fmt.Fprintln(os.Stderr, "server error:", err)
		os.Exit(1)
	}
}
