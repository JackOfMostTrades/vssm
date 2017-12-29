package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"errors"
)

// Copy from crypto/x509
var (
	oidPublicKeyRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidPublicKeyDSA   = asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 1}
	oidPublicKeyECDSA = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
)

// Copy from crypto/x509
var (
	oidNamedCurveP224 = asn1.ObjectIdentifier{1, 3, 132, 0, 33}
	oidNamedCurveP256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	oidNamedCurveP384 = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
	oidNamedCurveP521 = asn1.ObjectIdentifier{1, 3, 132, 0, 35}
)

// Copy from crypto/x509
func oidFromNamedCurve(curve elliptic.Curve) (asn1.ObjectIdentifier, bool) {
	switch curve {
	case elliptic.P224():
		return oidNamedCurveP224, true
	case elliptic.P256():
		return oidNamedCurveP256, true
	case elliptic.P384():
		return oidNamedCurveP384, true
	case elliptic.P521():
		return oidNamedCurveP521, true
	}

	return nil, false
}

type pkcs8Key struct {
	Version             int
	PrivateKeyAlgorithm []asn1.ObjectIdentifier
	PrivateKey          []byte
}

func rsa2pkcs8(key *rsa.PrivateKey) ([]byte, error) {
	var pkey pkcs8Key
	pkey.Version = 0
	pkey.PrivateKeyAlgorithm = make([]asn1.ObjectIdentifier, 1)
	pkey.PrivateKeyAlgorithm[0] = oidPublicKeyRSA
	pkey.PrivateKey = x509.MarshalPKCS1PrivateKey(key)

	return asn1.Marshal(pkey)
}

func ecdsa2pkcs8(priv *ecdsa.PrivateKey) ([]byte, error) {
	eckey, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, err
	}

	oidNamedCurve, ok := oidFromNamedCurve(priv.Curve)
	if !ok {
		return nil, errors.New("pkcs8: unknown elliptic curve")
	}

	// Per RFC5958, if publicKey is present, then version is set to v2(1) else version is set to v1(0).
	// But openssl set to v1 even publicKey is present
	var pkey pkcs8Key
	pkey.Version = 1
	pkey.PrivateKeyAlgorithm = make([]asn1.ObjectIdentifier, 2)
	pkey.PrivateKeyAlgorithm[0] = oidPublicKeyECDSA
	pkey.PrivateKeyAlgorithm[1] = oidNamedCurve
	pkey.PrivateKey = eckey

	return asn1.Marshal(pkey)
}
