package main

import (
	"os"

	"github.com/kidager/dmarcaid/internal/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
