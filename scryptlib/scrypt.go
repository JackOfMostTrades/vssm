package scryptlib

import (
	"crypto/hmac"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"golang.org/x/crypto/scrypt"
	"math"
	"strconv"
	"strings"
)

func CalcScrypt(pwd string) string {
	salt := make([]byte, 16)
	if n, err := rand.Read(salt); n != len(salt) || err != nil {
		if err != nil {
			panic(err)
		}
		panic(errors.New("Unable to generate salt."))
	}

	n := 32768
	r := 8
	p := 1
	val, err := scrypt.Key([]byte(pwd), salt, n, r, p, 32)
	if err != nil {
		panic(err)
	}

	return fmt.Sprintf("$s0$%X$%s$%s", (int(math.Log2(float64(n)))<<16)|(r<<8)|p,
		base64.StdEncoding.EncodeToString(salt),
		base64.StdEncoding.EncodeToString(val))
}

func VerifyScrypt(pwd, hash string) bool {
	parts := strings.Split(hash, "$")
	if len(parts) != 5 || parts[0] != "" {
		panic(errors.New("Invalid hash string."))
	}
	if parts[1] != "s0" {
		panic(fmt.Errorf("Unsupported MCF hash string: %s", parts[1]))
	}
	params, err := strconv.ParseUint(parts[2], 16, 32)
	if err != nil {
		panic(err)
	}
	n := (1 << ((params & 0xffff0000) >> 16))
	r := int(((params & 0xff00) >> 8))
	p := int(params & 0xff)

	salt, err := base64.StdEncoding.DecodeString(parts[3])
	if err != nil {
		panic(err)
	}
	value, err := base64.StdEncoding.DecodeString(parts[4])
	if err != nil {
		panic(err)
	}

	computed, err := scrypt.Key([]byte(pwd), salt, n, r, p, 32)
	return hmac.Equal(value, computed)
}
