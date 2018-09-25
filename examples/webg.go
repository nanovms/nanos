package main

import (
	"fmt"
	"log"
	"net/http"
)

var count int64

func handler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "unibooty %d", count)
	count++   
}

func main() {
	http.HandleFunc("/", handler)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
