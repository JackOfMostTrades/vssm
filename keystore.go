package main

import (
	"crypto"
	"time"
)

type SymmetricKey struct {
	key       []byte
	createdAt time.Time
}

type AsymmetricKey struct {
	keyType    string
	createdAt  time.Time
	key        crypto.PrivateKey
	pkcs8Bytes []byte
}

type MacKey struct {
	key       []byte
	createdAt time.Time
}

type keyStore struct {
	symmetricKeys  map[string]*SymmetricKey
	asymmetricKeys map[string]*AsymmetricKey
	macKeys        map[string]*MacKey
}
