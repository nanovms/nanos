package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
)

func main() {
	d1 := []byte("hello\ngo\n")
	err := ioutil.WriteFile("zig", d1, 0644)
	if err != nil {
		log.Fatal(err)
	}

    fileInfo, err := os.Stat("zig")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(fileInfo);
	files, err := ioutil.ReadDir("/")
	if err != nil {
		log.Fatal(err)
	}

	for _, f := range files {
		fmt.Println(f.Name(), f.Size(), f.IsDir())
	}
}
