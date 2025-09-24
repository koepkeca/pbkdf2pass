// Package pbkdf2pass is a wrapper for using pbkdf2 encoded passwords.
// It is based on the article "Salted Password Hashing - Doing it Right"
// written by Defuse Security (http://crackstation.net/hashing-security.htm)
// This provides functionality to store a salted keyed password.
package pbkdf2pass

import (
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"hash"
	"strconv"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

// These may be changed at any time
const (
	DEFAULT_ALGO     = "sha256"
	DEFAULT_ITER_LEN = 1000
	DEFAULT_SALT_LEN = 24
	DEFAULT_HASH_LEN = 24
)

// This map stores the hashing functions
var hashes map[string]func() hash.Hash

// A Config contains the basic configuration for encoding
// The Algo must be a valid key in the hashes map
// Empty Salts will be generated upon Encoding
type Config struct {
	Algo    string
	Salt    []byte
	IterLen int
	HashLen int
	SaltLen int
}

// Encode encodes a string using the configuration in c
// It returns a Password structure
func (c Config) Encode(s string) (p Password, e error) {
	if c.Salt == nil {
		sl := DEFAULT_SALT_LEN
		if c.SaltLen > 0 {
			sl = c.SaltLen
		}
		c.Salt, e = genRandBytes(sl)
	}
	if e != nil {
		e = fmt.Errorf(" error creating salt %s", e)
		return
	}
	if _, ok := hashes[c.Algo]; !ok {
		c.Algo = DEFAULT_ALGO
	}
	p.HashType = c.Algo
	h := hashes[c.Algo]
	p.IterLen = DEFAULT_ITER_LEN
	if c.IterLen > 0 {
		p.IterLen = c.IterLen
	}
	if c.HashLen == 0 {
		c.HashLen = DEFAULT_HASH_LEN
	}
	p.Salt = []byte(base64.StdEncoding.EncodeToString(c.Salt))
	enc := pbkdf2.Key([]byte(s), c.Salt, p.IterLen, c.HashLen, h)
	p.EncodedPass = []byte(base64.StdEncoding.EncodeToString(enc))
	return
}

// Password contains the password data
// EncodedPass and Salt are the base64-Encoded values, if you
// intend to work with the Raw Bytes, you MUST decode the values
// to get the raw bytes.
type Password struct {
	HashType    string
	EncodedPass []byte
	Salt        []byte
	IterLen     int
}

// String implements the fmt.Stringer interface
// Use this method to get a "writable" form of the password
func (p Password) String() (s string) {
	s = fmt.Sprintf("%s:%d:%s:%s", p.HashType, p.IterLen, p.Salt, p.EncodedPass)
	return
}

// Validate returns if String s matches the password stored in p
// It does this at "length-constant" time using the slowEquals method
func (p Password) Validate(s string) (v bool) {
	pDec, e := base64.StdEncoding.DecodeString(string(p.EncodedPass))
	if e != nil {
		return
	}
	sDec, e := base64.StdEncoding.DecodeString(string(p.Salt))
	if e != nil {
		return
	}
	tc := Config{Algo: p.HashType,
		IterLen: p.IterLen,
		Salt:    sDec,
		HashLen: len(pDec)}
	ch, e := tc.Encode(s)
	if e != nil {
		return
	}
	cDec, e := base64.StdEncoding.DecodeString(string(ch.EncodedPass))
	if e != nil {
		return
	}
	return slowEquals(pDec, cDec)
}

// FromString takes an encoded pasword structure and creates a Password
// e returns any decoding errors
func FromString(s string) (p Password, e error) {
	d := strings.Split(s, ":")
	if len(d) != 4 {
		e = fmt.Errorf(" decoded string has %d parts, needs 4", len(d))
		return
	}
	iLen, err := strconv.Atoi(d[1])
	if err != nil {
		e = fmt.Errorf(" decoded string has invalid iteration count")
		return
	}
	p.IterLen = iLen
	if _, ok := hashes[d[0]]; !ok {
		e = fmt.Errorf(" decoded string has invalid hash")
		return
	}
	p.HashType = d[0]
	p.Salt = []byte(d[2])
	p.EncodedPass = []byte(d[3])
	return
}

// init sets the hashes map
// if the spec adds new hashes later, add them here
func init() {
	hashes = make(map[string]func() hash.Hash)
	hashes["sha1"] = sha1.New
	hashes["sha224"] = sha256.New224
	hashes["sha256"] = sha256.New
	hashes["sha384"] = sha512.New384
	hashes["sha512"] = sha512.New512_256
	return
}

// slowEquals implements a "length-constant" time byte checker
// you can read more at https://crackstation.net/hashing-security.htm
func slowEquals(a []byte, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

// genRandBytes generates n random bytes using crypto/rand
func genRandBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}
