package main

import "testing"
import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"stash.corp.netflix.com/ps/vssm/logging"
	"stash.corp.netflix.com/ps/vssm/vssmpb"
	"strings"
	"time"
)

func TestGenerateKey(t *testing.T) {
	keyStore := &keyStore{
		symmetricKeys:  make(map[string]*SymmetricKey),
		asymmetricKeys: make(map[string]*AsymmetricKey),
		macKeys:        make(map[string]*MacKey),
	}
	service := AdminServiceImpl{
		appState: &appState{
			logger:       &stubLogger{},
			rootPassword: calcScrypt("adminPassword"),
			keyStore:     keyStore,
		},
	}

	_, err := service.GenerateKey(nil, &vssmpb.GenerateKeyRequest{
		AdminPassword: "badPassword",
		KeyName:       "sym",
		KeyType:       "SYMMETRIC",
		KeySize:       32,
	})
	if err != ErrBadPassword {
		t.Fatal("Did not receive bad password error.")
	}

	_, err = service.GenerateKey(nil, &vssmpb.GenerateKeyRequest{
		AdminPassword: "adminPassword",
		KeyName:       "sym",
		KeyType:       "SYMMETRIC",
		KeySize:       32,
	})
	if err != nil {
		t.Fatal(err)
	}
	if key, ok := keyStore.symmetricKeys["sym"]; !ok {
		t.Fatal("Keystore not updated with generated key.")
	} else {
		if len(key.key) != 32 {
			t.Fatal("Generated key had wrong length.")
		}
		if key.createdAt.Before(time.Now().Add(-5*time.Second)) ||
			key.createdAt.After(time.Now()) {
			t.Fatal("Generated key had invalid createdAt.")
		}
	}

	_, err = service.GenerateKey(nil, &vssmpb.GenerateKeyRequest{
		AdminPassword: "adminPassword",
		KeyName:       "myrsa",
		KeyType:       "ASYMMETRIC",
		KeySpec:       "RSA",
		KeySize:       2048,
	})
	if err != nil {
		t.Fatal(err)
	}
	if key, ok := keyStore.asymmetricKeys["myrsa"]; !ok {
		t.Fatal("Keystore not updated with generated key.")
	} else {
		if key.createdAt.Before(time.Now().Add(-5*time.Second)) ||
			key.createdAt.After(time.Now()) {
			t.Fatal("Generated key had invalid createdAt.")
		}
		if priv, ok := key.key.(*rsa.PrivateKey); !ok {
			t.Fatal("Generated key is not an RSA key.")
		} else {
			if priv.N.BitLen() != 2048 {
				t.Fatalf("Incorrect RSA generated bit length: %d", priv.N.BitLen())
			}
		}
	}

	_, err = service.GenerateKey(nil, &vssmpb.GenerateKeyRequest{
		AdminPassword: "adminPassword",
		KeyName:       "myecdsa",
		KeyType:       "ASYMMETRIC",
		KeySpec:       "EC",
		KeySize:       256,
	})
	if err != nil {
		t.Fatal(err)
	}
	if key, ok := keyStore.asymmetricKeys["myecdsa"]; !ok {
		t.Fatal("Keystore not updated with generated key.")
	} else {
		if key.createdAt.Before(time.Now().Add(-5*time.Second)) ||
			key.createdAt.After(time.Now()) {
			t.Fatal("Generated key had invalid createdAt.")
		}
		if priv, ok := key.key.(*ecdsa.PrivateKey); !ok {
			t.Fatal("Generated key is not an RSA key.")
		} else {
			if priv.Curve != elliptic.P256() {
				t.Fatal("Incorrect ECDSA curve for generated key.")
			}
		}
	}

	_, err = service.GenerateKey(nil, &vssmpb.GenerateKeyRequest{
		AdminPassword: "adminPassword",
		KeyName:       "mac",
		KeyType:       "MAC",
		KeySize:       32,
	})
	if err != nil {
		t.Fatal(err)
	}
	if key, ok := keyStore.macKeys["mac"]; !ok {
		t.Fatal("Keystore not updated with generated key.")
	} else {
		if len(key.key) != 32 {
			t.Fatal("Generated key had wrong length.")
		}
		if key.createdAt.Before(time.Now().Add(-5*time.Second)) ||
			key.createdAt.After(time.Now()) {
			t.Fatal("Generated key had invalid createdAt.")
		}
	}
}

func TestInjectKey(t *testing.T) {
	keyStore := &keyStore{
		symmetricKeys:  make(map[string]*SymmetricKey),
		asymmetricKeys: make(map[string]*AsymmetricKey),
		macKeys:        make(map[string]*MacKey),
	}
	service := AdminServiceImpl{
		appState: &appState{
			logger:       &stubLogger{},
			rootPassword: calcScrypt("adminPassword"),
			keyStore:     keyStore,
		},
	}

	symKey := randBytes(32)
	_, err := service.InjectKey(nil, &vssmpb.InjectKeyRequest{
		AdminPassword: "badPassword",
		KeyName:       "sym",
		KeyType:       "SYMMETRIC",
		Key:           symKey,
	})
	if err != ErrBadPassword {
		t.Fatal("Did not get bad password error")
	}

	_, err = service.InjectKey(nil, &vssmpb.InjectKeyRequest{
		AdminPassword: "adminPassword",
		KeyName:       "sym",
		KeyType:       "SYMMETRIC",
		Key:           symKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	if key, ok := keyStore.symmetricKeys["sym"]; !ok {
		t.Fatal("Keystore not updated with generated key.")
	} else {
		if !bytes.Equal(symKey, key.key) {
			t.Fatal("Inject key does not match requested injection.")
		}
		if key.createdAt.Before(time.Now().Add(-5*time.Second)) ||
			key.createdAt.After(time.Now()) {
			t.Fatal("Injected key had invalid createdAt.")
		}
	}

	rsaPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsaPrivKeyBytes, err := rsa2pkcs8(rsaPrivKey)
	if err != nil {
		t.Fatal(err)
	}
	_, err = service.InjectKey(nil, &vssmpb.InjectKeyRequest{
		AdminPassword: "adminPassword",
		KeyName:       "myrsa",
		KeyType:       "ASYMMETRIC",
		Key:           rsaPrivKeyBytes,
	})
	if err != nil {
		t.Fatal(err)
	}
	if key, ok := keyStore.asymmetricKeys["myrsa"]; !ok {
		t.Fatal("Keystore not updated with generated key.")
	} else {
		if key.createdAt.Before(time.Now().Add(-5*time.Second)) ||
			key.createdAt.After(time.Now()) {
			t.Fatal("Injected key had invalid createdAt.")
		}
		if !bytes.Equal(key.pkcs8Bytes, rsaPrivKeyBytes) {
			t.Fatal("Injected RSA key does not have matching PKCS8 bytes")
		}
		if priv, ok := key.key.(*rsa.PrivateKey); !ok {
			t.Fatal("Injected key is not an RSA key.")
		} else {
			if !bytes.Equal(priv.N.Bytes(), rsaPrivKey.N.Bytes()) ||
				!bytes.Equal(priv.D.Bytes(), rsaPrivKey.D.Bytes()) ||
				priv.E != rsaPrivKey.E {
				t.Fatal("Injected RSA key does not match generated RSA key.")
			}
		}
	}

	ecPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecPrivKeyBytes, err := ecdsa2pkcs8(ecPrivKey)
	if err != nil {
		t.Fatal(err)
	}
	_, err = service.InjectKey(nil, &vssmpb.InjectKeyRequest{
		AdminPassword: "adminPassword",
		KeyName:       "myecdsa",
		KeyType:       "ASYMMETRIC",
		Key:           ecPrivKeyBytes,
	})
	if err != nil {
		t.Fatal(err)
	}
	if key, ok := keyStore.asymmetricKeys["myecdsa"]; !ok {
		t.Fatal("Keystore not updated with generated key.")
	} else {
		if key.createdAt.Before(time.Now().Add(-5*time.Second)) ||
			key.createdAt.After(time.Now()) {
			t.Fatal("Injected key had invalid createdAt.")
		}
		if !bytes.Equal(key.pkcs8Bytes, ecPrivKeyBytes) {
			t.Fatal("Injected ECDSA key does not have matching PKCS8 bytes")
		}
		if priv, ok := key.key.(*ecdsa.PrivateKey); !ok {
			t.Fatal("Injected key is not an ECDSA key.")
		} else {
			if priv.Curve != ecPrivKey.Curve ||
				!bytes.Equal(priv.D.Bytes(), ecPrivKey.D.Bytes()) ||
				!bytes.Equal(priv.X.Bytes(), ecPrivKey.X.Bytes()) ||
				!bytes.Equal(priv.Y.Bytes(), ecPrivKey.Y.Bytes()) {
				t.Fatal("Injected ECDSA key does not match generated ECDSA key.")
			}
		}
	}

	macKey := randBytes(32)
	_, err = service.InjectKey(nil, &vssmpb.InjectKeyRequest{
		AdminPassword: "adminPassword",
		KeyName:       "mac",
		KeyType:       "MAC",
		Key:           macKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	if key, ok := keyStore.macKeys["mac"]; !ok {
		t.Fatal("Keystore not updated with generated key.")
	} else {
		if !bytes.Equal(macKey, key.key) {
			t.Fatal("Inject key does not match requested injection.")
		}
		if key.createdAt.Before(time.Now().Add(-5*time.Second)) ||
			key.createdAt.After(time.Now()) {
			t.Fatal("Injected key had invalid createdAt.")
		}
	}
}

func TestGenerateAndRestoreBackup(t *testing.T) {
	rpcCertificate, err := generateSelfSigned()
	if err != nil {
		t.Fatal(err)
	}

	service := AdminServiceImpl{
		appState: &appState{
			logger:       &stubLogger{},
			rootPassword: calcScrypt("adminPassword"),
			keyStore: &keyStore{
				symmetricKeys: map[string]*SymmetricKey{
					"foo": {
						key:       randBytes(32),
						createdAt: time.Now(),
					},
				},
				asymmetricKeys: map[string]*AsymmetricKey{
					"myrsa":   generateRsaKey(2048),
					"myecdsa": generateEcKey(elliptic.P256()),
				},
				macKeys: map[string]*MacKey{
					"bar": {
						key:       randBytes(32),
						createdAt: time.Now(),
					},
				},
			},
			rpcCertificate: rpcCertificate,
		},
	}
	_, err = service.GenerateBackup(nil, &vssmpb.GenerateBackupRequest{
		AdminPassword: "badPassword",
	})
	if err != ErrBadPassword {
		t.Fatal("Did not get bad password error.")
	}
	response, err := service.GenerateBackup(nil, &vssmpb.GenerateBackupRequest{
		AdminPassword: "adminPassword",
	})

	backupBlob := response.Backup

	oldKeyStore := service.appState.keyStore
	service.appState.keyStore = &keyStore{
		symmetricKeys:  make(map[string]*SymmetricKey),
		asymmetricKeys: make(map[string]*AsymmetricKey),
		macKeys:        make(map[string]*MacKey),
	}

	_, err = service.RestoreBackup(nil, &vssmpb.RestoreBackupRequest{
		AdminPassword: "badPassword",
		Backup:        backupBlob,
	})
	if err != ErrBadPassword {
		t.Fatal("Did not get bad password error.")
	}
	_, err = service.RestoreBackup(nil, &vssmpb.RestoreBackupRequest{
		AdminPassword: "adminPassword",
		Backup:        backupBlob,
	})

	newKeyStore := service.appState.keyStore
	if len(newKeyStore.symmetricKeys) != 1 ||
		len(newKeyStore.asymmetricKeys) != 2 ||
		len(newKeyStore.macKeys) != 1 {
		t.Fatal("Backup not correctly restored.")
	}
	if !bytes.Equal(oldKeyStore.symmetricKeys["foo"].key, newKeyStore.symmetricKeys["foo"].key) {
		t.Fatal("Symmetric key not correctly restored.")
	}
	if timeToUnixMillis(oldKeyStore.symmetricKeys["foo"].createdAt) != timeToUnixMillis(newKeyStore.symmetricKeys["foo"].createdAt) {
		t.Fatal("Symmetric key createdAt not correctly restored")
	}

	newAsymKey := newKeyStore.asymmetricKeys["myrsa"]
	oldAsymKey := oldKeyStore.asymmetricKeys["myrsa"]
	if timeToUnixMillis(newAsymKey.createdAt) != timeToUnixMillis(oldAsymKey.createdAt) ||
		newAsymKey.keyType != oldAsymKey.keyType ||
		!bytes.Equal(newAsymKey.pkcs8Bytes, oldAsymKey.pkcs8Bytes) {
		t.Fatal("Asymmetric key not correctly restored.")
	}
	if newRsaKey, ok := newAsymKey.key.(*rsa.PrivateKey); !ok {
		t.Fatal("RSA key not correctly restored.")
	} else {
		oldRsaKey := oldAsymKey.key.(*rsa.PrivateKey)
		if !bytes.Equal(newRsaKey.N.Bytes(), oldRsaKey.N.Bytes()) ||
			!bytes.Equal(newRsaKey.D.Bytes(), oldRsaKey.D.Bytes()) ||
			newRsaKey.E != oldRsaKey.E {
			t.Fatal("RSA key not correctly restored.")
		}
	}

	newAsymKey = newKeyStore.asymmetricKeys["myecdsa"]
	oldAsymKey = oldKeyStore.asymmetricKeys["myecdsa"]
	if timeToUnixMillis(newAsymKey.createdAt) != timeToUnixMillis(oldAsymKey.createdAt) ||
		newAsymKey.keyType != oldAsymKey.keyType ||
		!bytes.Equal(newAsymKey.pkcs8Bytes, oldAsymKey.pkcs8Bytes) {
		t.Fatal("Asymmetric key not correctly restored.")
	}
	if newEcdsaKey, ok := newAsymKey.key.(*ecdsa.PrivateKey); !ok {
		t.Fatal("ECDSA key not correctly restored.")
	} else {
		oldEcdsaKey := oldAsymKey.key.(*ecdsa.PrivateKey)
		if newEcdsaKey.Curve != oldEcdsaKey.Curve ||
			!bytes.Equal(newEcdsaKey.X.Bytes(), oldEcdsaKey.X.Bytes()) ||
			!bytes.Equal(newEcdsaKey.Y.Bytes(), oldEcdsaKey.Y.Bytes()) ||
			!bytes.Equal(newEcdsaKey.D.Bytes(), oldEcdsaKey.D.Bytes()) {
			t.Fatal("ECDSA key not correctly restored.")
		}
	}

	if !bytes.Equal(oldKeyStore.macKeys["bar"].key, newKeyStore.macKeys["bar"].key) {
		t.Fatal("Mac key not correctly restored.")
	}
	if timeToUnixMillis(oldKeyStore.macKeys["bar"].createdAt) != timeToUnixMillis(newKeyStore.macKeys["bar"].createdAt) {
		t.Fatal("Mac key createdAt not correctly restored")
	}

}

func TestListKeys(t *testing.T) {
	keyStore := &keyStore{
		symmetricKeys: map[string]*SymmetricKey{
			"foo": {
				key:       randBytes(32),
				createdAt: time.Now(),
			},
		},
		asymmetricKeys: map[string]*AsymmetricKey{
			"myrsa":   generateRsaKey(2048),
			"myecdsa": generateEcKey(elliptic.P256()),
		},
		macKeys: map[string]*MacKey{
			"bar": {
				key:       randBytes(40),
				createdAt: time.Now(),
			},
		},
	}

	service := AdminServiceImpl{
		appState: &appState{
			logger:       &stubLogger{},
			rootPassword: calcScrypt("adminPassword"),
			keyStore:     keyStore,
		},
	}
	_, err := service.ListKeys(nil, &vssmpb.ListKeysRequest{
		AdminPassword: "badPassword",
	})
	if err != ErrBadPassword {
		t.Fatal("Did not get bad password error.")
	}
	response, err := service.ListKeys(nil, &vssmpb.ListKeysRequest{
		AdminPassword: "adminPassword",
	})

	if len(response.SymmetricKey) != 1 {
		t.Fatal("Got incorrect symmetric keys in response")
	}
	symKey := response.SymmetricKey[0]
	if symKey.Name != "foo" || symKey.CreatedAt != timeToUnixMillis(keyStore.symmetricKeys["foo"].createdAt) ||
		symKey.KeyLength != 32 {
		t.Fatal("Got incorrect symmetric key in response")
	}

	if len(response.AsymmetricKey) != 2 {
		t.Fatal("Got incorrect symmetric keys in response")
	}
	var rsaKey, ecdsaKey *vssmpb.ListKeysAsymmetricKey
	for _, key := range response.AsymmetricKey {
		if key.Name == "myrsa" {
			rsaKey = key
		}
		if key.Name == "myecdsa" {
			ecdsaKey = key
		}
	}

	if rsaKey == nil || ecdsaKey == nil {
		t.Fatal("Got incorrect asymmetric key list in response")
	}
	rsaKeyBytes, err := x509.MarshalPKIXPublicKey(&keyStore.asymmetricKeys["myrsa"].key.(*rsa.PrivateKey).PublicKey)
	if err != nil {
		t.Fatalf("Can not marshal public key: %v.", err)
	}
	if rsaKey.Name != "myrsa" || rsaKey.CreatedAt != timeToUnixMillis(keyStore.asymmetricKeys["myrsa"].createdAt) ||
		rsaKey.KeySpec != "RSA" || !bytes.Equal(rsaKeyBytes, rsaKey.PublicKey) {
		t.Fatal("Got incorrect RSA key in response")
	}
	ecKeyBytes, err := x509.MarshalPKIXPublicKey(&keyStore.asymmetricKeys["myecdsa"].key.(*ecdsa.PrivateKey).PublicKey)
	if err != nil {
		t.Fatalf("Can not marshal public key: %v.", err)
	}
	if ecdsaKey.Name != "myecdsa" || ecdsaKey.CreatedAt != timeToUnixMillis(keyStore.asymmetricKeys["myecdsa"].createdAt) ||
		ecdsaKey.KeySpec != "EC" || !bytes.Equal(ecKeyBytes, ecdsaKey.PublicKey) {
		t.Fatal("Got incorrect EC key in response")
	}

	if len(response.MacKey) != 1 {
		t.Fatal("Got incorrect mac keys in response")
	}
	macKey := response.MacKey[0]
	if macKey.Name != "bar" || macKey.CreatedAt != timeToUnixMillis(keyStore.macKeys["bar"].createdAt) ||
		macKey.KeyLength != 40 {
		t.Fatal("Got incorrect mac key in response")
	}

	// Test getting a single key
	response, err = service.ListKeys(nil, &vssmpb.ListKeysRequest{
		AdminPassword: "adminPassword",
		KeyName:       "foo",
		KeyType:       "SYMMETRIC",
	})

	if len(response.SymmetricKey) != 1 || len(response.AsymmetricKey) != 0 || len(response.MacKey) != 0 {
		t.Fatal("Got incorrect keys in response")
	}
	symKey = response.SymmetricKey[0]
	if symKey.Name != "foo" || symKey.CreatedAt != timeToUnixMillis(keyStore.symmetricKeys["foo"].createdAt) ||
		symKey.KeyLength != 32 {
		t.Fatal("Got incorrect symmetric key in response")
	}
}

func TestGetLogs(t *testing.T) {
	logger := logging.New(logging.FATAL, logging.INFO)
	service := AdminServiceImpl{
		appState: &appState{
			logger:       logger,
			rootPassword: calcScrypt("adminPassword"),
		},
	}
	logger.Info("Test1")
	logger.Info("Test2")

	_, err := service.GetLogs(nil, &vssmpb.GetLogsRequest{
		AdminPassword: "badPassword",
	})
	if err != ErrBadPassword {
		t.Fatal("Did not get bad password error.")
	}

	response, err := service.GetLogs(nil, &vssmpb.GetLogsRequest{
		AdminPassword: "adminPassword",
	})
	if err != nil {
		t.Fatal("Error getting logs.")
	}

	if len(response.Log) != 3 {
		t.Fatalf("Got incorrect number of log lines: %d.", len(response.Log))
	}
	if !strings.HasSuffix(response.Log[0], "Test1") {
		t.Fatalf("Got incorrect first log: %s", response.Log[0])
	}
	if !strings.HasSuffix(response.Log[1], "Test2") {
		t.Fatalf("Got incorrect second log: %s", response.Log[1])
	}
	if !strings.HasSuffix(response.Log[2], "Retrieving logs...") {
		t.Fatalf("Got incorrect third log: %s", response.Log[2])
	}
}
