package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"github.com/golang/protobuf/jsonpb"
	"golang.org/x/net/context"
	"stash.corp.netflix.com/ps/vssm/vssmpb"
	"time"
)

type AdminServiceImpl struct {
	appState *appState
}

func (s *AdminServiceImpl) GenerateKey(ctx context.Context, request *vssmpb.GenerateKeyRequest) (*vssmpb.GenerateKeyResponse, error) {
	if request.KeyType == "SYMMETRIC" {
		if _, ok := s.appState.keyStore.symmetricKeys[request.KeyName]; ok {
			return nil, fmt.Errorf("Key with name %s already exists.", request.KeyName)
		}
		key := make([]byte, request.KeySize)
		if n, err := rand.Read(key); n != len(key) || err != nil {
			if err != nil {
				return nil, err
			}
			return nil, fmt.Errorf("Unable to generate key.")
		}

		_addSymmetricKey(s.appState.keyStore, request.KeyName, &SymmetricKey{
			key:       key,
			createdAt: time.Now(),
		})

	} else if request.KeyType == "ASYMMETRIC" {
		if _, ok := s.appState.keyStore.asymmetricKeys[request.KeyName]; ok {
			return nil, fmt.Errorf("Key with name %s already exists.", request.KeyName)
		}

		var privKey interface{}
		var privKeyBytes []byte

		if request.KeySpec == "RSA" {
			privateKey, err := rsa.GenerateKey(rand.Reader, int(request.KeySize))
			if err != nil {
				return nil, err
			}
			privKeyBytes, err = rsa2pkcs8(privateKey)
			if err != nil {
				return nil, err
			}
			privKey = privateKey

		} else if request.KeySpec == "EC" {
			var curve elliptic.Curve

			switch request.KeySize {
			case 226:
				curve = elliptic.P224()
			case 256:
				curve = elliptic.P256()
			case 384:
				curve = elliptic.P384()
			case 521:
				curve = elliptic.P521()
			default:
				return nil, fmt.Errorf("Unsupported ECDSA key size: %d", request.KeySize)
			}

			privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
			if err != nil {
				return nil, err
			}
			privKeyBytes, err = ecdsa2pkcs8(privateKey)
			if err != nil {
				return nil, err
			}
			privKey = privateKey

		} else {
			return nil, fmt.Errorf("Unsupported key spec: %s", request.KeySpec)
		}

		_addAsymmetricKey(s.appState.keyStore, request.KeyName, &AsymmetricKey{
			key:        privKey,
			keyType:    request.KeySpec,
			createdAt:  time.Now(),
			pkcs8Bytes: privKeyBytes,
		})

	} else if request.KeyType == "MAC" {
		if _, ok := s.appState.keyStore.macKeys[request.KeyName]; ok {
			return nil, fmt.Errorf("Key with name %s already exists.", request.KeyName)
		}
		key := make([]byte, request.KeySize)
		if n, err := rand.Read(key); n != len(key) || err != nil {
			if err != nil {
				return nil, err
			}
			return nil, fmt.Errorf("Unable to generate key.")
		}

		_addMacKey(s.appState.keyStore, request.KeyName, &MacKey{
			key:       key,
			createdAt: time.Now(),
		})

	} else {
		return nil, fmt.Errorf("Invalid key type: %s", request.KeyType)
	}

	// Push a synchronization update to all other known hosts
	pushSyncNow(s.appState)

	return &vssmpb.GenerateKeyResponse{}, nil
}

func _addSymmetricKey(keyStore *keyStore, keyName string, key *SymmetricKey) {
	newMap := make(map[string]*SymmetricKey)
	for name, value := range keyStore.symmetricKeys {
		newMap[name] = value
	}
	newMap[keyName] = key
	keyStore.symmetricKeys = newMap
}
func _addAsymmetricKey(keyStore *keyStore, keyName string, key *AsymmetricKey) {
	newMap := make(map[string]*AsymmetricKey)
	for name, value := range keyStore.asymmetricKeys {
		newMap[name] = value
	}
	newMap[keyName] = key
	keyStore.asymmetricKeys = newMap
}
func _addMacKey(keyStore *keyStore, keyName string, key *MacKey) {
	newMap := make(map[string]*MacKey)
	for name, value := range keyStore.macKeys {
		newMap[name] = value
	}
	newMap[keyName] = key
	keyStore.macKeys = newMap
}

func (s *AdminServiceImpl) InjectKey(ctx context.Context, request *vssmpb.InjectKeyRequest) (*vssmpb.InjectKeyResponse, error) {

	if request.KeyType == "SYMMETRIC" {
		if _, ok := s.appState.keyStore.symmetricKeys[request.KeyName]; ok {
			return nil, fmt.Errorf("Key with name %s already exists.", request.KeyName)
		}
		_addSymmetricKey(s.appState.keyStore, request.KeyName, &SymmetricKey{
			key:       request.Key,
			createdAt: time.Now(),
		})

	} else if request.KeyType == "ASYMMETRIC" {
		if _, ok := s.appState.keyStore.asymmetricKeys[request.KeyName]; ok {
			return nil, fmt.Errorf("Key with name %s already exists.", request.KeyName)
		}

		privKey, err := x509.ParsePKCS8PrivateKey(request.Key)
		if err != nil {
			return nil, err
		}

		var keyType string
		switch privKey.(type) {
		case *rsa.PrivateKey:
			keyType = "RSA"
		case *ecdsa.PrivateKey:
			keyType = "EC"
		default:
			return nil, fmt.Errorf("Unsupported key type: %T", privKey)
		}

		_addAsymmetricKey(s.appState.keyStore, request.KeyName, &AsymmetricKey{
			key:        privKey,
			keyType:    keyType,
			createdAt:  time.Now(),
			pkcs8Bytes: request.Key,
		})

	} else if request.KeyType == "MAC" {
		if _, ok := s.appState.keyStore.macKeys[request.KeyName]; ok {
			return nil, fmt.Errorf("Key with name %s already exists.", request.KeyName)
		}
		_addMacKey(s.appState.keyStore, request.KeyName, &MacKey{
			key:       request.Key,
			createdAt: time.Now(),
		})

	} else {
		return nil, fmt.Errorf("Invalid key type: %s", request.KeyType)
	}

	return nil, errors.New("Unimplemented")
}

func (s *AdminServiceImpl) GenerateBackup(ctx context.Context, request *vssmpb.GenerateBackupRequest) (*vssmpb.GenerateBackupResponse, error) {
	backup_message := appStateToSynchronizeMessage(s.appState)
	backup_message.KnownClients = nil
	marshaller := &jsonpb.Marshaler{}
	backup_message_str, err := marshaller.MarshalToString(backup_message)
	if err != nil {
		return nil, err
	}

	encryption_key := make([]byte, 32)
	if n, err := rand.Read(encryption_key); n != len(encryption_key) || err != nil {
		if err != nil {
			return nil, err
		}
		return nil, errors.New("Unable to generate enough random bytes.")
	}

	encrypted_backup_blob, err := _internalEncrypt([]byte(backup_message_str), encryption_key)
	if err != nil {
		return nil, err
	}

	encrypted_private_key, err := rsa.EncryptOAEP(sha256.New(), rand.Reader,
		s.appState.rpcCertificate.Leaf.PublicKey.(*rsa.PublicKey), encryption_key, nil)
	if err != nil {
		return nil, err
	}

	return &vssmpb.GenerateBackupResponse{
		Backup: &vssmpb.BackupBlob{
			EncryptionKey:  encrypted_private_key,
			Version:        1,
			Timestamp:      timeToUnixMillis(time.Now()),
			EncryptedState: encrypted_backup_blob,
		},
	}, nil
}

func (s *AdminServiceImpl) RestoreBackup(ctx context.Context, request *vssmpb.RestoreBackupRequest) (*vssmpb.RestoreBackupResponse, error) {
	if request.Backup.Version != 1 {
		return nil, errors.New("Unsupported backup version.")
	}

	encryption_key, err := rsa.DecryptOAEP(sha256.New(), rand.Reader,
		s.appState.rpcCertificate.PrivateKey.(*rsa.PrivateKey), request.Backup.EncryptionKey, nil)
	if err != nil {
		return nil, err
	}
	plaintext_backup_blob, err := _internalDecrypt(request.Backup.EncryptedState, encryption_key)
	if err != nil {
		return nil, err
	}

	var backup_mesage vssmpb.SynchronizeStateResponse
	err = jsonpb.UnmarshalString(string(plaintext_backup_blob), &backup_mesage)
	if err != nil {
		// Specifically do not return the actual error in case it leaks something about the decrypted blob
		return nil, errors.New("Unable to decrypt backup.")
	}

	err = synchronizeStateFromResponse(s.appState, &backup_mesage)
	if err != nil {
		return nil, err
	}

	return &vssmpb.RestoreBackupResponse{}, nil
}

func _internalEncrypt(input []byte, key []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

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

	output := make([]byte, len(nonce))
	copy(output, nonce)
	output = aeadCipher.Seal(output, nonce, input, nil)
	return output, nil
}

func _internalDecrypt(input []byte, key []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aeadCipher, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}
	nonce := input[0:aeadCipher.NonceSize()]
	input = input[aeadCipher.NonceSize():]
	output, err := aeadCipher.Open(nil, nonce, input, nil)
	if err != nil {
		return nil, err
	}
	return output, nil
}

func _encodePublicKey(priv interface{}) ([]byte, error) {
	switch priv.(type) {
	case *rsa.PrivateKey:
		return x509.MarshalPKIXPublicKey(&priv.(*rsa.PrivateKey).PublicKey)
	case *ecdsa.PrivateKey:
		return x509.MarshalPKIXPublicKey(&priv.(*ecdsa.PrivateKey).PublicKey)
	default:
		return nil, fmt.Errorf("Unhandled key type: %T", priv)
	}
}

func (s *AdminServiceImpl) ListKeys(ctx context.Context, request *vssmpb.ListKeysRequest) (*vssmpb.ListKeysResponse, error) {
	if len(request.KeyName) > 0 {
		if request.KeyType == "SYMMETRIC" {
			key, ok := s.appState.keyStore.symmetricKeys[request.KeyName]
			if !ok {
				return nil, errors.New("No key by that name exists.")
			}
			return &vssmpb.ListKeysResponse{
				SymmetricKey: []*vssmpb.ListKeysSymmetricKey{
					{
						Name:      request.KeyName,
						CreatedAt: timeToUnixMillis(key.createdAt),
						KeyLength: uint64(len(key.key)),
					},
				},
			}, nil
		} else if request.KeyType == "ASYMMETRIC" {
			key, ok := s.appState.keyStore.asymmetricKeys[request.KeyName]
			if !ok {
				return nil, errors.New("No key by that name exists.")
			}
			pubBytes, err := _encodePublicKey(key.key)
			if err != nil {
				return nil, err
			}
			return &vssmpb.ListKeysResponse{
				AsymmetricKey: []*vssmpb.ListKeysAsymmetricKey{
					{
						Name:      request.KeyName,
						CreatedAt: timeToUnixMillis(key.createdAt),
						KeySpec:   key.keyType,
						PublicKey: pubBytes,
					},
				},
			}, nil
		} else if request.KeyType == "MAC" {
			key, ok := s.appState.keyStore.macKeys[request.KeyName]
			if !ok {
				return nil, errors.New("No key by that name exists.")
			}
			return &vssmpb.ListKeysResponse{
				MacKey: []*vssmpb.ListKeysMacKey{
					{
						Name:      request.KeyName,
						CreatedAt: timeToUnixMillis(key.createdAt),
						KeyLength: uint64(len(key.key)),
					},
				},
			}, nil
		} else {
			return nil, fmt.Errorf("Unsupported key type: %s", request.KeyType)
		}
	} else {

		response := &vssmpb.ListKeysResponse{
			SymmetricKey:  make([]*vssmpb.ListKeysSymmetricKey, 0, len(s.appState.keyStore.symmetricKeys)),
			AsymmetricKey: make([]*vssmpb.ListKeysAsymmetricKey, 0, len(s.appState.keyStore.asymmetricKeys)),
			MacKey:        make([]*vssmpb.ListKeysMacKey, 0, len(s.appState.keyStore.macKeys)),
		}

		for keyName, key := range s.appState.keyStore.symmetricKeys {
			response.SymmetricKey = append(response.SymmetricKey, &vssmpb.ListKeysSymmetricKey{
				Name:      keyName,
				CreatedAt: timeToUnixMillis(key.createdAt),
				KeyLength: uint64(len(key.key)),
			})
		}

		for keyName, key := range s.appState.keyStore.asymmetricKeys {
			pubBytes, err := _encodePublicKey(key.key)
			if err != nil {
				return nil, err
			}
			response.AsymmetricKey = append(response.AsymmetricKey, &vssmpb.ListKeysAsymmetricKey{
				Name:      keyName,
				CreatedAt: timeToUnixMillis(key.createdAt),
				KeySpec:   key.keyType,
				PublicKey: pubBytes,
			})
		}

		for keyName, key := range s.appState.keyStore.macKeys {
			response.MacKey = append(response.MacKey, &vssmpb.ListKeysMacKey{
				Name:      keyName,
				CreatedAt: timeToUnixMillis(key.createdAt),
				KeyLength: uint64(len(key.key)),
			})
		}

		return response, nil
	}
}
