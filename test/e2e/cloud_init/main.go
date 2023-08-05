package main

import (
        "fmt"
        "os"
)

func main() {
        b, ok := os.LookupEnv("VAR1")
        if ok {
                fmt.Println(b)
        }
}

