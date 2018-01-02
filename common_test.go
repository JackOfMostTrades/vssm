package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	mathrand "math/rand"
	"stash.corp.netflix.com/ps/vssm/logging"
	"time"
)

type stubLogger struct{}

func (l *stubLogger) Debug(format string, args ...interface{}) {}
func (l *stubLogger) Info(format string, args ...interface{})  {}
func (l *stubLogger) Warn(format string, args ...interface{})  {}
func (l *stubLogger) Error(format string, args ...interface{}) {}
func (l *stubLogger) Fatal(format string, args ...interface{}) {}

func (l *stubLogger) GetLogs() []*logging.Log {
	return nil
}

func randBytes(n int) []byte {
	out := make([]byte, n)
	m, err := mathrand.Read(out)
	if err != nil {
		panic(err)
	}
	if m != n {
		panic("Unable to read enough bytes.")
	}
	return out
}

func mustBase64Decode(s string) []byte {
	out, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return out
}

func generateRsaKey(keySize int) *AsymmetricKey {
	priv, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		panic(err)
	}
	pkcs8Bytes, err := rsa2pkcs8(priv)
	if err != nil {
		panic(err)
	}
	return &AsymmetricKey{
		keyType:    "RSA",
		createdAt:  time.Now(),
		key:        priv,
		pkcs8Bytes: pkcs8Bytes,
	}
}

func generateEcKey(curve elliptic.Curve) *AsymmetricKey {
	priv, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		panic(err)
	}

	pkcs8Bytes, err := ecdsa2pkcs8(priv)
	if err != nil {
		panic(err)
	}
	return &AsymmetricKey{
		keyType:    "EC",
		createdAt:  time.Now(),
		key:        priv,
		pkcs8Bytes: pkcs8Bytes,
	}
}

func parseAsymmetricKey(pkcs8b64 string) *AsymmetricKey {
	bytes, err := base64.StdEncoding.DecodeString(pkcs8b64)
	if err != nil {
		panic(err)
	}
	priv, err := x509.ParsePKCS8PrivateKey(bytes)
	if err != nil {
		panic(err)
	}

	var keyType string
	switch priv.(type) {
	case *rsa.PrivateKey:
		keyType = "RSA"
	case *ecdsa.PrivateKey:
		keyType = "EC"
	default:
		panic(fmt.Sprintf("Unsupported key type: %T", priv))
	}

	return &AsymmetricKey{
		keyType:    keyType,
		createdAt:  time.Now(),
		key:        priv,
		pkcs8Bytes: bytes,
	}
}
