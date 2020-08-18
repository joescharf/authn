package main

import "fmt"

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	fmt.Printf("libauthn %v, commit %v, built at %v\n", version, commit, date)
}
