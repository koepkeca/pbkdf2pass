package main

import (
	"fmt"
	"log"

	"github.com/koepkeca/pbkdf2_pass"
)

func main() {
	c := pbkdf2_pass.Config{}
	p, e := c.Encode("Testing1234")
	if e != nil {
		log.Fatal(e)
	}
	fmt.Printf("%s\n", p)
	return
}
