[![GoDoc](https://godoc.org/github.com/koepkeca/pbkdf2pass?status.svg)](https://godoc.org/github.com/koepkeca/pbkdf2pass)
[![Go Report Card](https://goreportcard.com/badge/github.com/koepkeca/pbkdf2pass)](https://goreportcard.com/report/github.com/koepkeca/pbkdf2pass)

# Overview

pbkdf2pass is a library written in go that provides a wrapper for encoding passwords. This is useful for storing password hashes in databases or flat files for users in a system. It is intended to be moderately more secure than simple MD5 or SHA1 hashes which can be quickly decoded using Rainbow Tables or other methods. This library is based off of the work by Defuse Security and [can be found here](https://crackstation.net/hashing-security.htm). This library now also uses the Go Standard Library which properly implements slow_equals and can be [reviewed here.](https://github.com/golang/go/blob/d7a38adf4c81f0fa83203e37844192182b22680a/src/crypto/internal/fips140/subtle/constant_time.go)

# Installation

To install the library you just do a go get:

```
go get github.com/koepkeca/pbkdf2pass
```

# Data Format

The hashed data is stored in a string with a ':' as a separator. The order is static and is as follows:

```
hash_string:iteration_length:salt:password
```

where:
* hash_string is a string defining the hash type [valid types are sha1, sha224, sha256, sha384, sha512] the default type is sha256
* iteration_length is an integer (int) that defines the number of iterations for the pbkdf2 encoding
* salt is a base64 encoded string containing the salt
* password is a base64 encoded string containing the password

# Usage

To generate a new encoded password you will need to provide some configuration information. The default values are set as constants and may be changed at any time without corrupting existing hashes. You can also override the defaults by setting the new value in the configuration structure. For example, if you wanted to use SHA384 encoding with an iteration count of 4000 just create a Config struct as follows:

```
c := pbkdf2pass.Config{Algo:"sha384",IterLen:4000}
```
## Creating a password hash

To encode a string using the parameters setup in your config you call the Encode method with the string you would like to encode, this returns a Password structure containing the encoded data.

```
c := pbkdf2pass.Config{}
p, e := c.Encode("Test123")
if e != nil {
	log.Fatal(e)
}
```

p now contains a Password structure containing the relevant data.

Password implements the [fmt.Stringer interface](https://golang.org/pkg/fmt/#Stringer) so you can use it accordingly.

To get the encoded string data you can either use:

```
encStr := p.String()
```

**or**

```
encStr := fmt.Sprintf("%s",encStr)
```

## Comparing a challenge request

There are two steps you need to perform to validate a challenge. The following example illustrates validating a challenge. For the purposes of this example we will call the challenge string "challenge" and the pre-encoded password "key":

```
//assume key is a pre-encoded string (see above) and challenge is a 
//plain-text string entered by a user (this would be the password we are comparing against)

c := pbkdf2pass.Config{}
encKey, err := c.FromString(key)
if err != nil {
    //If there is an error decoding the key, you need to handle it here
    log.Fatal(" error decoding key from string.. failing")
}
//Now encKey contains the data loaded in from our string, we can just
//do a validate on the challenge
isValidPass := encKey.Validate(challenge)
//isValidPass now is true if the password matches, false if it does not
```
Complete coded examples are included in the example directory and include a basic [encoding](https://github.com/koepkeca/pbkdf2pass/blob/v0/example/encode.go) and [decoding](https://github.com/koepkeca/pbkdf2pass/blob/v0/example/decode.go) example.



## Gotcha's and caveats

* If any part of a Config is not explicitly set, it uses the default values.
* The Validate method does not provide an error. There could be a base64 decoding error, however, we currently ignore it. Future versions may provide logging. It currently silently fails as a security precaution.
* Ensure your storage method has adequate space for your hash length. Keep in mind that the salt and hash are stored as a base64 encoded value and will require more space than just the byte length.

