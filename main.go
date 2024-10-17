package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
)

func handler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "Hello from the Go api!")
}

func main() {
	port := os.Getenv("PORT")
	http.HandleFunc("/", handler)
	log.Println("listening on " + port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}