package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"
)

var count int64

func argsHandler(w http.ResponseWriter, r *http.Request) {
	var s string
	for i := 0; i < len(os.Args); i++ {
		s += os.Args[i]
	}
	fmt.Fprint(w, s)
}

func reqTestHandler(w http.ResponseWriter, r *http.Request) {
	resp, err := http.Get("https://ops.city")
	if err != nil {
		fmt.Println(err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
	}

	fmt.Fprint(w, string(body))
}

func envHandler(w http.ResponseWriter, r *http.Request) {

	var s string
	env := os.Environ()
	for i := 0; i < len(env); i++ {
		s += env[i]
	}
	fmt.Fprint(w, s)
}

func tsHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "%s\n", time.Now())
}

func handler(w http.ResponseWriter, r *http.Request) {

	fmt.Fprintf(w, "unibooty %d", count)
	count++
}

func main() {

	http.HandleFunc("/", handler)
	http.HandleFunc("/req", reqTestHandler)
	http.HandleFunc("/args", argsHandler)
	http.HandleFunc("/env", envHandler)
	http.HandleFunc("/ts", tsHandler)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
