package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"stash.corp.netflix.com/ps/vssm/vssmpb"
	"strings"
	"testing"
	"time"
)

const EC2_METADATA_AMI = "ami-ea165990"
const EC2_RSA2048 = "MIAGCSqGSIb3DQEHAqCAMIACAQExDzANBglghkgBZQMEAgEFADCABgkqhkiG9w0BBwGggCSABIIB1HsKICAiYXZhaWxhYmlsaXR5Wm9uZSIgOiAidXMtZWFzdC0xZSIsCiAgImRldnBheVByb2R1Y3RDb2RlcyIgOiBudWxsLAogICJtYXJrZXRwbGFjZVByb2R1Y3RDb2RlcyIgOiBudWxsLAogICJ2ZXJzaW9uIiA6ICIyMDE3LTA5LTMwIiwKICAiaW5zdGFuY2VJZCIgOiAiaS0wNTU5NTBiOWNmYmNlMGNlMyIsCiAgImJpbGxpbmdQcm9kdWN0cyIgOiBudWxsLAogICJpbnN0YW5jZVR5cGUiIDogIm00LmxhcmdlIiwKICAicGVuZGluZ1RpbWUiIDogIjIwMTctMTItMjlUMDU6MzQ6MDdaIiwKICAicHJpdmF0ZUlwIiA6ICIxMDAuNjYuMzkuMTU0IiwKICAiYWNjb3VudElkIiA6ICIxNzk3MjcxMDExOTQiLAogICJhcmNoaXRlY3R1cmUiIDogIng4Nl82NCIsCiAgImtlcm5lbElkIiA6IG51bGwsCiAgInJhbWRpc2tJZCIgOiBudWxsLAogICJpbWFnZUlkIiA6ICJhbWktZWExNjU5OTAiLAogICJyZWdpb24iIDogInVzLWVhc3QtMSIKfQAAAAAAADGCAf8wggH7AgEBMGkwXDELMAkGA1UEBhMCVVMxGTAXBgNVBAgTEFdhc2hpbmd0b24gU3RhdGUxEDAOBgNVBAcTB1NlYXR0bGUxIDAeBgNVBAoTF0FtYXpvbiBXZWIgU2VydmljZXMgTExDAgkAsWnMQBVZpBkwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0xNzEyMjkwNTM0MTJaMC8GCSqGSIb3DQEJBDEiBCAnRmg+lfohgYY+mmmARsuY+eDhZnxkqSnq3QFOzB0N2jANBgkqhkiG9w0BAQEFAASCAQB8huDo5kOLVGKjGeT3EfK43by0SqS3FThw2VIL4dnFf1OV3c53DT2YjIq4nf9IXFCuE51ch7TLsY9TWTGbLr+U1UF9Y6sahEAfJpp3Vk4KyMwuiELm0/glExksUMgy51tOOAqOMXwoHPBKtnWx9ZVSmv/KUrU3R3armHBrUrcOdZxF2OMPIanWyTJ3aO1uPX4LZOTS/vnM792ED1YlZ1bKl8iu1U0WXEKqc4arkmeqvDhvIs2cg4EKr4QE103dAGCSZzRd+IKd6ZiKivcZP4ul1006IJSrAP0VK4N+PS0bw9xzacMOPPdeP/JiGYlCiiT2tSXwNWB/nKeeSDyPoa4YAAAAAAAA"
const EC2_BAD_DAT = "MIAGCSqGSIb3DQEHAqCAMIACAQExDzANBglghkgBZQMEAgEFADCABgkqhkiG9w0BBwGggCSABIIB1HsKICAiYXZhaWxhYmlsaXR5Wm9uZSIgOiAidXMtZWFzdC0xZSIsCiAgImRldnBheVByb2R1Y3RDb2RlcyIgOiBudWxsLAogICJtYXJrZXRwbGFjZVByb2R1Y3RDb2RlcyIgOiBudWxsLAogICJ2ZXJzaW9uIiA6ICIyMDE3LTA5LTMwIiwKICAiaW5zdGFuY2VJZCIgOiAiaS0wNTU5NTBiOWNmYmNlMGNlMyIsCiAgImJpbGxpbmdQcm9kdWN0cyIgOiBudWxsLAogICJpbnN0YW5jZVR5cGUiIDogIm00LmxhcmdlIiwKICAicGVuZGluZ1RpbWUiIDogIjIwMTctMTItMjlUMDU6MzQ6MDdaIiwKICAicHJpdmF0ZUlwIiA6ICIxMDAuNjYuMzkuMTU0IiwKICAiYWNjb3VudElkIiA6ICIxNzk3MjcxMDExOTQiLAogICJhcmNoaXRlY3R1cmUiIDogIng4Nl82NCIsCiAgImtlcm5lbElkIiA6IG51bGwsCiAgInJhbWRpc2tJZCIgOiBudWxsLAogICJpbWFnZUlkIiA6ICJhbWktMDAwMDAwMDAiLAogICJyZWdpb24iIDogInVzLWVhc3QtMSIKfQAAAAAAADGCAf8wggH7AgEBMGkwXDELMAkGA1UEBhMCVVMxGTAXBgNVBAgTEFdhc2hpbmd0b24gU3RhdGUxEDAOBgNVBAcTB1NlYXR0bGUxIDAeBgNVBAoTF0FtYXpvbiBXZWIgU2VydmljZXMgTExDAgkAsWnMQBVZpBkwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0xNzEyMjkwNTM0MTJaMC8GCSqGSIb3DQEJBDEiBCAnRmg+lfohgYY+mmmARsuY+eDhZnxkqSnq3QFOzB0N2jANBgkqhkiG9w0BAQEFAASCAQB8huDo5kOLVGKjGeT3EfK43by0SqS3FThw2VIL4dnFf1OV3c53DT2YjIq4nf9IXFCuE51ch7TLsY9TWTGbLr+U1UF9Y6sahEAfJpp3Vk4KyMwuiELm0/glExksUMgy51tOOAqOMXwoHPBKtnWx9ZVSmv/KUrU3R3armHBrUrcOdZxF2OMPIanWyTJ3aO1uPX4LZOTS/vnM792ED1YlZ1bKl8iu1U0WXEKqc4arkmeqvDhvIs2cg4EKr4QE103dAGCSZzRd+IKd6ZiKivcZP4ul1006IJSrAP0VK4N+PS0bw9xzacMOPPdeP/JiGYlCiiT2tSXwNWB/nKeeSDyPoa4YAAAAAAAA"
const EC2_BAD_SIG = "MIAGCSqGSIb3DQEHAqCAMIACAQExDzANBglghkgBZQMEAgEFADCABgkqhkiG9w0BBwGggCSABIIB1HsKICAiYXZhaWxhYmlsaXR5Wm9uZSIgOiAidXMtZWFzdC0xZSIsCiAgImRldnBheVByb2R1Y3RDb2RlcyIgOiBudWxsLAogICJtYXJrZXRwbGFjZVByb2R1Y3RDb2RlcyIgOiBudWxsLAogICJ2ZXJzaW9uIiA6ICIyMDE3LTA5LTMwIiwKICAiaW5zdGFuY2VJZCIgOiAiaS0wNTU5NTBiOWNmYmNlMGNlMyIsCiAgImJpbGxpbmdQcm9kdWN0cyIgOiBudWxsLAogICJpbnN0YW5jZVR5cGUiIDogIm00LmxhcmdlIiwKICAicGVuZGluZ1RpbWUiIDogIjIwMTctMTItMjlUMDU6MzQ6MDdaIiwKICAicHJpdmF0ZUlwIiA6ICIxMDAuNjYuMzkuMTU0IiwKICAiYWNjb3VudElkIiA6ICIxNzk3MjcxMDExOTQiLAogICJhcmNoaXRlY3R1cmUiIDogIng4Nl82NCIsCiAgImtlcm5lbElkIiA6IG51bGwsCiAgInJhbWRpc2tJZCIgOiBudWxsLAogICJpbWFnZUlkIiA6ICJhbWktZWExNjU5OTAiLAogICJyZWdpb24iIDogInVzLWVhc3QtMSIKfQAAAAAAADGCAf8wggH7AgEBMGkwXDELMAkGA1UEBhMCVVMxGTAXBgNVBAgTEFdhc2hpbmd0b24gU3RhdGUxEDAOBgNVBAcTB1NlYXR0bGUxIDAeBgNVBAoTF0FtYXpvbiBXZWIgU2VydmljZXMgTExDAgkAsWnMQBVZpBkwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0xNzEyMjkwNTM0MTJaMC8GCSqGSIb3DQEJBDEiBCAnRmg+lfohgYY+mmmARsuY+eDhZnxkqSnq3QFOzB0N2jANBgkqhkiG9w0BAQEFAASCAQB9huDo5kOLVGKjGeT3EfK43by0SqS3FThw2VIL4dnFf1OV3c53DT2YjIq4nf9IXFCuE51ch7TLsY9TWTGbLr+U1UF9Y6sahEAfJpp3Vk4KyMwuiELm0/glExksUMgy51tOOAqOMXwoHPBKtnWx9ZVSmv/KUrU3R3armHBrUrcOdZxF2OMPIanWyTJ3aO1uPX4LZOTS/vnM792ED1YlZ1bKl8iu1U0WXEKqc4arkmeqvDhvIs2cg4EKr4QE103dAGCSZzRd+IKd6ZiKivcZP4ul1006IJSrAP0VK4N+PS0bw9xzacMOPPdeP/JiGYlCiiT2tSXwNWB/nKeeSDyPoa4YAAAAAAAA"

func TestBootstrapSlave(t *testing.T) {
	service := InternalServiceImpl{
		appState: &appState{
			rpcPrivateKeyPkcs8: []byte("bootstrap private key"),
			myAmi:              EC2_METADATA_AMI,
		},
	}

	cmsBytes, err := base64.StdEncoding.DecodeString(EC2_RSA2048)
	if err != nil {
		t.Fatal(err)
	}
	response, err := service.BootstrapSlave(nil, &vssmpb.BootstrapSlaveRequest{
		ClientCms: cmsBytes,
	})
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(response.RpcPrivateKey, []byte("bootstrap private key")) {
		t.Fatal("Got incorrect RPC private key from bootstrap response.")
	}

	service.appState.myAmi = "ami-00000000"
	response, err = service.BootstrapSlave(nil, &vssmpb.BootstrapSlaveRequest{
		ClientCms: cmsBytes,
	})
	if err == nil || err.Error() != "Client image id ami-ea165990 doesn't match instance image id ami-00000000" {
		t.Fatalf("Got invalid error with mismatched AMI: %v", err)
	}

	cmsBytes, err = base64.StdEncoding.DecodeString(EC2_BAD_DAT)
	if err != nil {
		t.Fatal(err)
	}
	response, err = service.BootstrapSlave(nil, &vssmpb.BootstrapSlaveRequest{
		ClientCms: cmsBytes,
	})
	if err == nil || !strings.HasPrefix(err.Error(), "pkcs7: Message digest mismatch") {
		t.Fatalf("Got invalid error with bad data on CMS: %v", err)
	}

	cmsBytes, err = base64.StdEncoding.DecodeString(EC2_BAD_SIG)
	if err != nil {
		t.Fatal(err)
	}
	response, err = service.BootstrapSlave(nil, &vssmpb.BootstrapSlaveRequest{
		ClientCms: cmsBytes,
	})
	if err == nil || !strings.HasPrefix(err.Error(), "crypto/rsa: verification error") {
		t.Fatalf("Got invalid error with bad signature on CMS: %v", err)
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
