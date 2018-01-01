package main

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"encoding/asn1"
	"fmt"
	"golang.org/x/net/context"
	"io"
	"math/big"
	"stash.corp.netflix.com/ps/vssm/vssmpb"
	"strings"
)

type VssmServiceImpl struct {
	appState *appState
}

func (s *VssmServiceImpl) SymmetricEncrypt(ctx context.Context, request *vssmpb.SymmetricEncryptRequest) (*vssmpb.SymmetricEncryptResponse, error) {
	algParts := strings.Split(request.Algorithm, "/")
	var err error
	var key *SymmetricKey
	var ok bool
	if key, ok = s.appState.keyStore.symmetricKeys[request.KeyName]; !ok {
		return nil, fmt.Errorf("Invalid key name: %s", request.KeyName)
	}
	if len(algParts) != 3 {
		return nil, fmt.Errorf("Invalid algorithm specification: %s", request.Algorithm)
	}

	var c cipher.Block
	if algParts[0] == "AES" {
		c, err = aes.NewCipher(key.key)
		if err != nil {
			return nil, err
		}
	} else if algParts[0] == "DES" {
		c, err = des.NewCipher(key.key)
		if err != nil {
			return nil, err
		}
	} else if algParts[0] == "3DES" {
		c, err = des.NewTripleDESCipher(key.key)
		if err != nil {
			return nil, err
		}
	} else {
		return nil, fmt.Errorf("Invalid cipher: %s", algParts[0])
	}

	var paddedInput []byte
	if algParts[2] == "NoPadding" {
		paddedInput = request.Input
	} else if algParts[2] == "PKCS5Padding" || algParts[2] == "PKCS7Padding" {
		paddedInput, err = pkcs7Pad(request.Input, c.BlockSize())
		if err != nil {
			return nil, err
		}
	} else {
		return nil, fmt.Errorf("Unsupported padding mode: %s", algParts[2])
	}

	var output []byte
	if algParts[1] == "ECB" {
		bs := c.BlockSize()
		output := make([]byte, len(paddedInput))
		for i := 0; i < len(paddedInput); i += bs {
			c.Encrypt(output[i:i+bs], paddedInput[i:i+bs])
		}
	} else if algParts[1] == "CTR" {
		iv := make([]byte, c.BlockSize())
		if n, err := rand.Read(iv); n != len(iv) || err != nil {
			if err != nil {
				return nil, err
			}
			return nil, fmt.Errorf("Unable to generate random IV bytes.")
		}
		streamCipher := cipher.NewCTR(c, iv)
		output = make([]byte, len(iv)+len(paddedInput))
		copy(output, iv)
		streamCipher.XORKeyStream(output[len(iv):], paddedInput)
	} else if algParts[1] == "CBC" {
		iv := make([]byte, c.BlockSize())
		if n, err := rand.Read(iv); n != len(iv) || err != nil {
			if err != nil {
				return nil, err
			}
			return nil, fmt.Errorf("Unable to generate random IV bytes.")
		}
		blockCipher := cipher.NewCBCEncrypter(c, iv)
		output = make([]byte, len(iv)+len(paddedInput))
		copy(output, iv)
		blockCipher.CryptBlocks(output[len(iv):], paddedInput)
	} else if algParts[1] == "GCM" {
		aeadCipher, err := cipher.NewGCM(c)
		if err != nil {
			return nil, err
		}
		nonce := make([]byte, aeadCipher.NonceSize())
		if n, err := rand.Read(nonce); n != len(nonce) || err != nil {
			if err != nil {
				return nil, err
			}
			return nil, fmt.Errorf("Unable to generate random nonce bytes.")
		}

		output = make([]byte, len(nonce))
		copy(output, nonce)
		output = aeadCipher.Seal(output, nonce, paddedInput, nil)
	} else {
		return nil, fmt.Errorf("Unsupported block mode: %s", algParts[1])
	}

	return &vssmpb.SymmetricEncryptResponse{
		Output: output,
	}, nil
}
func (s *VssmServiceImpl) SymmetricDecrypt(ctx context.Context, request *vssmpb.SymmetricDecryptRequest) (*vssmpb.SymmetricDecryptResponse, error) {
	algParts := strings.Split(request.Algorithm, "/")
	var err error
	var key *SymmetricKey
	var ok bool
	if key, ok = s.appState.keyStore.symmetricKeys[request.KeyName]; !ok {
		return nil, fmt.Errorf("Invalid key name: %s", request.KeyName)
	}
	if len(algParts) != 3 {
		return nil, fmt.Errorf("Invalid algorithm specification: %s", request.Algorithm)
	}
	var c cipher.Block
	if algParts[0] == "AES" {
		c, err = aes.NewCipher(key.key)
		if err != nil {
			return nil, err
		}
	} else if algParts[0] == "DES" {
		c, err = des.NewCipher(key.key)
		if err != nil {
			return nil, err
		}
	} else if algParts[0] == "3DES" {
		c, err = des.NewTripleDESCipher(key.key)
		if err != nil {
			return nil, err
		}
	} else {
		return nil, fmt.Errorf("Invalid cipher: %s", algParts[0])
	}

	var output []byte
	if algParts[1] == "ECB" {
		bs := c.BlockSize()
		output := make([]byte, len(request.Input))
		for i := 0; i < len(request.Input); i += bs {
			c.Decrypt(output[i:i+bs], request.Input[i:i+bs])
		}
	} else if algParts[1] == "CTR" {
		iv := request.Input[0:c.BlockSize()]
		input := request.Input[c.BlockSize():]
		streamCipher := cipher.NewCTR(c, iv)
		output = make([]byte, len(input))
		streamCipher.XORKeyStream(output, input)
	} else if algParts[1] == "CBC" {
		iv := request.Input[0:c.BlockSize()]
		input := request.Input[c.BlockSize():]
		blockCipher := cipher.NewCBCDecrypter(c, iv)
		output = make([]byte, len(input))
		blockCipher.CryptBlocks(output, input)
	} else if algParts[1] == "GCM" {
		aeadCipher, err := cipher.NewGCM(c)
		if err != nil {
			return nil, err
		}
		nonce := request.Input[0:aeadCipher.NonceSize()]
		input := request.Input[aeadCipher.NonceSize():]
		output, err = aeadCipher.Open(nil, nonce, input, nil)
		if err != nil {
			return nil, err
		}

	} else {
		return nil, fmt.Errorf("Unsupported block mode: %s", algParts[1])
	}

	var unpaddedOutput []byte
	if algParts[2] == "NoPadding" {
		unpaddedOutput = output
	} else if algParts[2] == "PKCS5Padding" || algParts[2] == "PKCS7Padding" {
		unpaddedOutput, err = pkcs7Unpad(output, c.BlockSize())
		if err != nil {
			return nil, err
		}
	} else {
		return nil, fmt.Errorf("Unsupported padding mode: %s", algParts[2])
	}

	return &vssmpb.SymmetricDecryptResponse{
		Output: unpaddedOutput,
	}, nil
}

func (s *VssmServiceImpl) AsymmetricEncrypt(ctx context.Context, request *vssmpb.AsymmetricEncryptRequest) (*vssmpb.AsymmetricEncryptResponse, error) {

	var key *AsymmetricKey
	var ok bool
	if key, ok = s.appState.keyStore.asymmetricKeys[request.KeyName]; !ok {
		return nil, fmt.Errorf("Invalid key name: %s", request.KeyName)
	}

	var output []byte
	if strings.HasPrefix(request.Algorithm, "RSA-OAEP/") {
		algParts := strings.Split(request.Algorithm, "/")
		if len(algParts) != 2 {
			return nil, fmt.Errorf("Invalid algorithm: %s", request.Algorithm)
		}
		var hash crypto.Hash
		if algParts[1] == "SHA1" {
			hash = crypto.SHA1
		} else if algParts[1] == "SHA256" {
			hash = crypto.SHA256
		} else {
			return nil, fmt.Errorf("Invalid hash algorithm: %s", algParts[1])
		}

		var err error
		output, err = rsa.EncryptOAEP(hash.New(), rand.Reader, &key.key.(*rsa.PrivateKey).PublicKey, request.Input, nil)
		if err != nil {
			return nil, err
		}
	} else if request.Algorithm == "RSA" {
		var err error
		output, err = rsa.EncryptPKCS1v15(rand.Reader, &key.key.(*rsa.PrivateKey).PublicKey, request.Input)
		if err != nil {
			return nil, err
		}
	} else {
		return nil, fmt.Errorf("Invalid algorithm: %s", request.Algorithm)
	}

	return &vssmpb.AsymmetricEncryptResponse{
		Output: output,
	}, nil
}
func (s *VssmServiceImpl) AsymmetricDecrypt(ctx context.Context, request *vssmpb.AsymmetricDecryptRequest) (*vssmpb.AsymmetricDecryptResponse, error) {

	var key *AsymmetricKey
	var ok bool
	if key, ok = s.appState.keyStore.asymmetricKeys[request.KeyName]; !ok {
		return nil, fmt.Errorf("Invalid key name: %s", request.KeyName)
	}

	var output []byte
	if strings.HasPrefix(request.Algorithm, "RSA-OAEP/") {
		algParts := strings.Split(request.Algorithm, "/")
		if len(algParts) != 2 {
			return nil, fmt.Errorf("Invalid algorithm: %s", request.Algorithm)
		}
		var hash crypto.Hash
		if algParts[1] == "SHA1" {
			hash = crypto.SHA1
		} else if algParts[1] == "SHA256" {
			hash = crypto.SHA256
		} else {
			return nil, fmt.Errorf("Invalid hash algorithm: %s", algParts[1])
		}

		var err error
		output, err = rsa.DecryptOAEP(hash.New(), rand.Reader, key.key.(*rsa.PrivateKey), request.Input, nil)
		if err != nil {
			return nil, err
		}
	} else if request.Algorithm == "RSA" {
		var err error
		output, err = rsa.DecryptPKCS1v15(rand.Reader, key.key.(*rsa.PrivateKey), request.Input)
		if err != nil {
			return nil, err
		}
	} else {
		return nil, fmt.Errorf("Invalid algorithm: %s", request.Algorithm)
	}

	return &vssmpb.AsymmetricDecryptResponse{
		Output: output,
	}, nil
}

type ecdsaSignature struct {
	R *big.Int
	S *big.Int
}

func _ecdsaSign(rand io.Reader, priv *ecdsa.PrivateKey, hashed []byte) ([]byte, error) {
	r, s, err := ecdsa.Sign(rand, priv, hashed)
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(ecdsaSignature{
		R: r,
		S: s,
	})
}
func _ecdsaVerify(pub *ecdsa.PublicKey, hashed []byte, signature []byte) (bool, error) {
	var sig ecdsaSignature
	_, err := asn1.Unmarshal(signature, &sig)
	if err != nil {
		return false, err
	}
	return ecdsa.Verify(pub, hashed, sig.R, sig.S), nil
}

func (s *VssmServiceImpl) AsymmetricSign(ctx context.Context, request *vssmpb.AsymmetricSignRequest) (*vssmpb.AsymmetricSignResponse, error) {
	var key *AsymmetricKey
	var ok bool
	if key, ok = s.appState.keyStore.asymmetricKeys[request.KeyName]; !ok {
		return nil, fmt.Errorf("Invalid key name: %s", request.KeyName)
	}

	rsaSigner := func(hash crypto.Hash, hashed []byte) ([]byte, error) {
		return rsa.SignPKCS1v15(rand.Reader, key.key.(*rsa.PrivateKey), hash, hashed)
	}
	ecdsaSigner := func(hash crypto.Hash, hashed []byte) ([]byte, error) {
		return _ecdsaSign(rand.Reader, key.key.(*ecdsa.PrivateKey), hashed)
	}

	var hash crypto.Hash
	var signer func(crypto.Hash, []byte) ([]byte, error)

	if request.Algorithm == "SHA1withRSA" {
		hash = crypto.SHA1
		signer = rsaSigner
	} else if request.Algorithm == "SHA256withRSA" {
		hash = crypto.SHA256
		signer = rsaSigner
	} else if request.Algorithm == "SHA1withECDSA" {
		hash = crypto.SHA1
		signer = ecdsaSigner
	} else if request.Algorithm == "SHA256withECDSA" {
		hash = crypto.SHA256
		signer = ecdsaSigner
	} else {
		return nil, fmt.Errorf("Invalid algorithm: %s", request.Algorithm)
	}

	var hashed []byte
	if len(request.Input) > 0 {
		h := hash.New()
		h.Write(request.Input)
		hashed = h.Sum(nil)
	} else {
		hashed = request.Hashed
	}

	output, err := signer(hash, hashed)
	if err != nil {
		return nil, err
	}

	return &vssmpb.AsymmetricSignResponse{
		Output: output,
	}, nil
}
func (s *VssmServiceImpl) AsymmetricVerify(ctx context.Context, request *vssmpb.AsymmetricVerifyRequest) (*vssmpb.AsymmetricVerifyResponse, error) {
	var key *AsymmetricKey
	var ok bool
	if key, ok = s.appState.keyStore.asymmetricKeys[request.KeyName]; !ok {
		return nil, fmt.Errorf("Invalid key name: %s", request.KeyName)
	}

	rsaVerifier := func(hash crypto.Hash, hashed []byte) (bool, error) {
		err := rsa.VerifyPKCS1v15(&key.key.(*rsa.PrivateKey).PublicKey, hash, hashed, request.Signature)
		if err == nil {
			return true, nil
		} else if err == rsa.ErrVerification {
			return false, nil
		} else {
			return false, err
		}
	}
	ecdsaVerifier := func(hash crypto.Hash, hashed []byte) (bool, error) {
		return _ecdsaVerify(&key.key.(*ecdsa.PrivateKey).PublicKey, hashed, request.Signature)
	}

	var hash crypto.Hash
	var verifier func(crypto.Hash, []byte) (bool, error)

	if request.Algorithm == "SHA1withRSA" {
		hash = crypto.SHA1
		verifier = rsaVerifier
	} else if request.Algorithm == "SHA256withRSA" {
		hash = crypto.SHA256
		verifier = rsaVerifier
	} else if request.Algorithm == "SHA1withECDSA" {
		hash = crypto.SHA1
		verifier = ecdsaVerifier
	} else if request.Algorithm == "SHA256withECDSA" {
		hash = crypto.SHA256
		verifier = ecdsaVerifier
	} else {
		return nil, fmt.Errorf("Invalid algorithm: %s", request.Algorithm)
	}

	var hashed []byte
	if len(request.Input) > 0 {
		h := hash.New()
		h.Write(request.Input)
		hashed = h.Sum(nil)
	} else {
		hashed = request.Hashed
	}

	valid, err := verifier(hash, hashed)
	if err != nil {
		return nil, err
	}

	return &vssmpb.AsymmetricVerifyResponse{
		Valid: valid,
	}, nil
}
func (s *VssmServiceImpl) HmacCreate(ctx context.Context, request *vssmpb.HmacCreateRequest) (*vssmpb.HmacCreateResponse, error) {
	var key *MacKey
	var ok bool
	if key, ok = s.appState.keyStore.macKeys[request.KeyName]; !ok {
		return nil, fmt.Errorf("Invalid key name: %s", request.KeyName)
	}

	var hash crypto.Hash
	if request.Algorithm == "SHA1" {
		hash = crypto.SHA1
	} else if request.Algorithm == "SHA256" {
		hash = crypto.SHA256
	} else {
		return nil, fmt.Errorf("Invalid algorithm: %s", request.Algorithm)
	}

	h := hmac.New(hash.New, key.key)
	h.Write(request.Input)
	output := h.Sum(nil)

	return &vssmpb.HmacCreateResponse{
		Output: output,
	}, nil
}
func (s *VssmServiceImpl) HmacVerify(ctx context.Context, request *vssmpb.HmacVerifyRequest) (*vssmpb.HmacVerifyResponse, error) {
	var key *MacKey
	var ok bool
	if key, ok = s.appState.keyStore.macKeys[request.KeyName]; !ok {
		return nil, fmt.Errorf("Invalid key name: %s", request.KeyName)
	}

	var hash crypto.Hash
	if request.Algorithm == "SHA1" {
		hash = crypto.SHA1
	} else if request.Algorithm == "SHA256" {
		hash = crypto.SHA256
	} else {
		return nil, fmt.Errorf("Invalid algorithm: %s", request.Algorithm)
	}

	h := hmac.New(hash.New, key.key)
	h.Write(request.Input)
	output := h.Sum(nil)

	valid := hmac.Equal(output, request.Hmac)

	return &vssmpb.HmacVerifyResponse{
		Valid: valid,
	}, nil
}
