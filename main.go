package main

import (
	"fmt"
	"os"
)

func main() {
	loadConfig()
	go statusLoop()
	go ddnsLoop()
	if err := serve(); err != nil {
		fmt.Fprintln(os.Stderr, "server error:", err)
		os.Exit(1)
	}
}
