package main

import (
	"flag"
	"fmt"
	"log"
	"os"
)

var (
	listenPort string
	pwdFile    string
	debugFile  string
)

func init() {
	flag.StringVar(&listenPort, "l", "", "Reverse-proxy mode: listen for inbound connections (required)")
	flag.StringVar(&pwdFile, "k", "", "Path to the password file (required)")
	flag.StringVar(&debugFile, "d", "myapp.log", "Debug file for logging")
}

func main() {
	flag.Parse()

	// Check if required flags are provided
	if pwdFile == "" {
		fmt.Println("Error: -k (password file) are required flags.")
		flag.Usage()
		os.Exit(1)
	}
	// Setup logging
	if debugFile != "" {
		f, err := os.OpenFile(debugFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Fatalf("Error opening log file: %v", err)
		}
		defer f.Close()
		log.SetOutput(f)
	}

	// Read password from the password file
	password, err := os.ReadFile(pwdFile)
	if err != nil {
		log.Fatalf("Failed to read password file: %v", err)
	}

	log.Println("Application started")

	if flag.NArg() < 2 {
		log.Fatalf("Error: destination address and port are required")
	}
	// Determine operation mode and run
	destination := flag.Arg(0) + ":" + flag.Arg(1)

	if listenPort != "" {
		log.Printf("Running in server mode, listening on port %s", listenPort)
		runProxy(destination, password)
	}

	if listenPort == "" {
		log.Printf("Running in client mode, connecting to %s", destination)
		runClient(destination, password)
	}
}
