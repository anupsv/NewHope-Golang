package main

import (
	  "fmt"
	_ "NewHope-Golang"

	"NewHope-Golang"
)

func main() {


	privAlice, pubAlice, err := NewHope_golang.GenerateKeyPair(NewHope_golang.RandomBytes(32)[0])
	fmt.Println(privAlice)

}
