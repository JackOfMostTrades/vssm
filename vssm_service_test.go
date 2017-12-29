package main

import (
	"crypto"
	"encoding/base64"
	"testing"
)

func TestSimpleHash(t *testing.T) {
	hash := crypto.SHA256
	h := hash.New()
	h.Write([]byte("xyz\n"))
	hashBytes := h.Sum(nil)
	t.Logf("Hash: %s", base64.StdEncoding.EncodeToString(hashBytes))
}
