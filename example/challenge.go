package main

import (
	"fmt"
	"log"

	"github.com/koepkeca/pbkdf2pass"
)

//ENCODED_STRING is a pre-encoded version of the string Testing1234
const (
	ENCODED_STRING = "sha256:1000:ZrKNvl0eIWr6GNtBYDCSdMOjQvchBeBZ:NWLjFJRWx6opWqCultjr7XvvLBjYzMRN"
)

func main() {
	p, e := pbkdf2pass.FromString(ENCODED_STRING)
	if e != nil {
		log.Fatal("invalid encoded string")
	}
	ok := p.Validate("Testing1234")
	fmt.Println(ok)
	ok = p.Validate("BADPASSWORD")
	fmt.Println(ok)
	return
}
