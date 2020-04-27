package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"
	"net"
	"crypto/tls"
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
		fmt.Fprint(w, err)
		return
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

func filePersistenceHandler(w http.ResponseWriter, r *http.Request) {

	f, err := os.OpenFile("a.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		panic(err)
	}

	if _, err := f.Write([]byte("something")); err != nil {
		panic(err)
	}

	if err := f.Close(); err != nil {
		panic(err)
	}

	dat, err := ioutil.ReadFile("a.log")
	if err != nil {
		panic(err)
	}
	fmt.Fprint(w, string(dat))
}

func main() {
	port := "8080"

	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	http.HandleFunc("/", handler)
	http.HandleFunc("/req", reqTestHandler)
	http.HandleFunc("/args", argsHandler)
	http.HandleFunc("/env", envHandler)
	http.HandleFunc("/ts", tsHandler)
	http.HandleFunc("/file", filePersistenceHandler)

	done := make(chan bool)
	ready := make(chan bool)
	go func() {
		listener, err := net.Listen("tcp", ":" + port)
		if err != nil {
			panic(err)
		}
		ready <- true
		log.Fatal(http.Serve(listener, nil))
		done <- true
	}()
	<-ready
	fmt.Printf("Server started on port %v\n", port)
	<-done
}
