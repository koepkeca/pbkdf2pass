package pbkdf2pass

import (
	"testing"
)

func Test_slow_equals_true(t *testing.T) {
	test := slowEquals([]byte("testing"), []byte("testing"))
	if !test {
		t.Fail()
	}
}

func Test_slow_equals_false(t *testing.T) {
	test := slowEquals([]byte("test"), []byte("testing"))
	if test {
		t.Fail()
	}
}

func Test_encode(t *testing.T) {
	c := Config{Algo: "sha512"}
	p, e := c.Encode("Woobie42")
	if e != nil {
		t.Fail()
	}
	if p.EncodedPass == nil {
		t.Fail()
	}
}

func Test_FromString(t *testing.T) {
	_, e := FromString("sha512:1000:vV2DN8wjhnxJ5fzzW7J8uSkTz5LoHrhe:qO57dNINgr14UFEdzHOnRxDNcngyICL0")
	if e != nil {
		t.Fail()
	}
}

func Test_Validation(t *testing.T) {
	_, e := FromString("sha512:1000:B9jD3IgHyU9sp87bvjaQ3/+ZKEQ5WDPP:fNalV6hq5U3pl1rE3w56p6x4oypbHCmw")
	if e != nil {
		t.Fail()
	}
}

func Test_EmptyFromString(t *testing.T) {
	_, e := FromString("")
	if e == nil {
		t.Fail()
	}
}

func Test_EmptyValidate(t *testing.T) {
	c := Config{}
	p, e := c.Encode("example")
	if e != nil {
		t.Fail()
	}
	rlt := p.Validate("")
	if rlt == true {
		t.Fail()
	}
}

func Test_Validate(t *testing.T) {
	c := Config{}
	p, e := c.Encode("Testing123")
	if e != nil {
		t.Fail()
	}
	rlt := p.Validate("Testing123")
	if !rlt {
		t.Fail()
	}
}

func Test_NonStandard_Hash_Len(t *testing.T) {
	c := Config{HashLen: 36}
	p, e := c.Encode("Testing456")
	if e != nil {
		t.Fail()
	}
	rlt := p.Validate("Testing456")
	if !rlt {
		t.Fail()
	}
}

func Test_NonStandard_Salt_Len(t *testing.T) {
	c := Config{SaltLen: 8}
	p, e := c.Encode("Testing890")
	if e != nil {
		t.Fail()
	}
	rlt := p.Validate("Testing890")
	if !rlt {
		t.Fail()
	}
}

func Test_Diff_Iter_Len(t *testing.T) {
	c := Config{IterLen: 4000}
	p, e := c.Encode("Example1234")
	if e != nil {
		t.Fail()
	}
	hashStr := p.String()
	z, e := FromString(hashStr)
	if e != nil {
		t.Fail()
	}
	if !z.Validate("Example1234") {
		t.Fail()
	}
}

func Test_Unicode_Pass(t *testing.T) {
	c := Config{}
	p, e := c.Encode("笑い男")
	if e != nil {
		t.Fail()
	}
	hashStr := p.String()
	z, e := FromString(hashStr)
	if e != nil {
		t.Fail()
	}
	if !z.Validate("笑い男") {
		t.Fail()
	}
}
