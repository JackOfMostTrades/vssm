package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"errors"
	"stash.corp.netflix.com/ps/vssm/vssmpb"
	"testing"
	"time"
)

type testCloudProvider struct{}

func (p *testCloudProvider) GetPeers() ([]string, error) {
	return nil, nil
}
func (p *testCloudProvider) GetAttestation() ([]byte, error) {
	return nil, nil
}
func (p *testCloudProvider) VerifyAttestation(attestation []byte) error {
	if bytes.Equal(attestation, []byte("good")) {
		return nil
	}
	return errors.New("Bad attestation")
}

func TestBootstrapSlave(t *testing.T) {
	service := InternalServiceImpl{
		appState: &appState{
			cloudProvider:      &testCloudProvider{},
			rpcPrivateKeyPkcs8: []byte("bootstrap private key"),
		},
	}

	response, err := service.BootstrapSlave(nil, &vssmpb.BootstrapSlaveRequest{
		Attestation: []byte("good"),
	})
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(response.RpcPrivateKey, []byte("bootstrap private key")) {
		t.Fatal("Got incorrect RPC private key from bootstrap response.")
	}

	response, err = service.BootstrapSlave(nil, &vssmpb.BootstrapSlaveRequest{
		Attestation: []byte("bad"),
	})
	if err == nil || err.Error() != "Bad attestation" {
		t.Fatalf("Got invalid error with bad attestation: %v", err)
	}
}

func TestSynchronizeState(t *testing.T) {
	keyStore := &keyStore{
		symmetricKeys: map[string]*SymmetricKey{
			"foo": {
				createdAt: time.Now(),
				key:       randBytes(32),
			},
		},
		asymmetricKeys: map[string]*AsymmetricKey{
			"myrsa":   generateRsaKey(2048),
			"myecdsa": generateEcKey(elliptic.P256()),
		},
		macKeys: map[string]*MacKey{
			"bar": {
				createdAt: time.Now(),
				key:       randBytes(32),
			},
		},
	}
	service := InternalServiceImpl{
		appState: &appState{
			keyStore: keyStore,
		},
	}
	response, err := service.SynchronizeState(nil, &vssmpb.SynchronizeStateRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if len(response.SymmetricKey) != 1 || len(response.AsymmetricKey) != 2 || len(response.MacKey) != 1 {
		t.Fatal("Got incorrect synchronization response.")
	}
	symKey := response.SymmetricKey[0]
	if symKey.Name != "foo" || !bytes.Equal(symKey.Key, keyStore.symmetricKeys["foo"].key) ||
		symKey.CreatedAt != timeToUnixMillis(keyStore.symmetricKeys["foo"].createdAt) {
		t.Fatal("Got incorrect symmetric key in response.")
	}

	asymKeys := make(map[string]*vssmpb.AsymmetricKey)
	for _, key := range response.AsymmetricKey {
		asymKeys[key.Name] = key
	}
	if asymKeys["myrsa"].Name != "myrsa" || asymKeys["myrsa"].KeyType != "RSA" ||
		!bytes.Equal(asymKeys["myrsa"].Key, keyStore.asymmetricKeys["myrsa"].pkcs8Bytes) ||
		asymKeys["myrsa"].CreatedAt != timeToUnixMillis(keyStore.asymmetricKeys["myrsa"].createdAt) {
		t.Fatal("Got incorrect RSA key in response.")
	}
	if asymKeys["myecdsa"].Name != "myecdsa" || asymKeys["myecdsa"].KeyType != "EC" ||
		!bytes.Equal(asymKeys["myecdsa"].Key, keyStore.asymmetricKeys["myecdsa"].pkcs8Bytes) ||
		asymKeys["myecdsa"].CreatedAt != timeToUnixMillis(keyStore.asymmetricKeys["myecdsa"].createdAt) {
		t.Fatal("Got incorrect EC key in response.")
	}

	macKey := response.MacKey[0]
	if macKey.Name != "bar" || !bytes.Equal(macKey.Key, keyStore.macKeys["bar"].key) ||
		macKey.CreatedAt != timeToUnixMillis(keyStore.macKeys["bar"].createdAt) {
		t.Fatal("Got incorrect mac key in response.")
	}
}

func TestSynchronizeStatePush(t *testing.T) {
	oldSymKey := randBytes(32)
	keyStore := &keyStore{
		symmetricKeys: map[string]*SymmetricKey{
			"foo": {
				createdAt: time.Now(),
				key:       oldSymKey,
			},
		},
		asymmetricKeys: map[string]*AsymmetricKey{
			"myrsa":   generateRsaKey(2048),
			"myecdsa": generateEcKey(elliptic.P256()),
		},
		macKeys: map[string]*MacKey{
			"bar": {
				createdAt: time.Now(),
				key:       randBytes(32),
			},
		},
	}
	service := InternalServiceImpl{
		appState: &appState{
			logger:   &stubLogger{},
			keyStore: keyStore,
		},
	}

	newSymKey := randBytes(32)
	newRsaKey := generateRsaKey(2048)
	newEcKey := generateEcKey(elliptic.P256())
	newMacKey := randBytes(32)
	_, err := service.SynchronizeStatePush(nil, &vssmpb.SynchronizeStatePushRequest{
		SynchronizeStateMessage: &vssmpb.SynchronizeStateResponse{
			SymmetricKey: []*vssmpb.SymmetricKey{
				// Push an old version of "foo". With the older createdAt date, it should not be used
				{
					Name:      "foo",
					CreatedAt: timeToUnixMillis(keyStore.symmetricKeys["foo"].createdAt.Add(-1 * time.Hour)),
					Key:       randBytes(32),
				},
				// A new key should get merged
				{
					Name:      "symTest",
					CreatedAt: timeToUnixMillis(time.Now()),
					Key:       newSymKey,
				},
			},
			AsymmetricKey: []*vssmpb.AsymmetricKey{
				{
					Name:      "myrsa2",
					CreatedAt: timeToUnixMillis(time.Now()),
					KeyType:   "RSA",
					Key:       newRsaKey.pkcs8Bytes,
				},
				{
					Name:      "myecdsa2",
					CreatedAt: timeToUnixMillis(time.Now()),
					KeyType:   "EC",
					Key:       newEcKey.pkcs8Bytes,
				},
			},
			MacKey: []*vssmpb.MacKey{
				{
					Name:      "macTest",
					CreatedAt: timeToUnixMillis(time.Now()),
					Key:       newMacKey,
				},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	if key, ok := keyStore.symmetricKeys["foo"]; !ok {
		t.Fatal("Could not find old symmetric key in keystore.")
	} else {
		if !bytes.Equal(oldSymKey, key.key) {
			t.Fatal("Old symmetric was overwritten.")
		}
	}
	if key, ok := keyStore.symmetricKeys["symTest"]; !ok {
		t.Fatal("Could not find new symmetric key in keystore.")
	} else {
		if !bytes.Equal(newSymKey, key.key) {
			t.Fatal("New symmetric key was not copied correctly.")
		}
	}

	if key, ok := keyStore.asymmetricKeys["myrsa2"]; !ok {
		t.Fatal("Could not find new RSA key in keystore.")
	} else {
		if !bytes.Equal(newRsaKey.key.(*rsa.PrivateKey).N.Bytes(), key.key.(*rsa.PrivateKey).N.Bytes()) ||
			!bytes.Equal(newRsaKey.key.(*rsa.PrivateKey).D.Bytes(), key.key.(*rsa.PrivateKey).D.Bytes()) ||
			newRsaKey.key.(*rsa.PrivateKey).E != key.key.(*rsa.PrivateKey).E {
			t.Fatal("New RSA key was not correctly copied.")
		}
	}
	if key, ok := keyStore.asymmetricKeys["myecdsa2"]; !ok {
		t.Fatal("Could not find new ECDSA key in keystore.")
	} else {
		newPriv := newEcKey.key.(*ecdsa.PrivateKey)
		priv := key.key.(*ecdsa.PrivateKey)
		if newPriv.Curve != priv.Curve || !bytes.Equal(newPriv.X.Bytes(), priv.X.Bytes()) ||
			!bytes.Equal(newPriv.Y.Bytes(), priv.Y.Bytes()) ||
			!bytes.Equal(newPriv.D.Bytes(), priv.D.Bytes()) {
			t.Fatal("New EC key was not correctly copied.")
		}
	}

	if key, ok := keyStore.macKeys["macTest"]; !ok {
		t.Fatal("Could not find new mac key in keystore.")
	} else {
		if !bytes.Equal(newMacKey, key.key) {
			t.Fatal("New mac key was not copied correctly.")
		}
	}
}
