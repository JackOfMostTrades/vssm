package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"github.com/golang/protobuf/jsonpb"
	"github.com/golang/protobuf/proto"
	"math/big"
	"net/http"
	"stash.corp.netflix.com/ps/vssm/vssmpb"
	"strings"
	"testing"
	"time"
)

func generateClientCaAndCert() (*x509.Certificate, tls.Certificate, error) {
	caPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Client CA",
		},
		NotBefore: time.Now().Add(-24 * time.Hour),
		NotAfter:  time.Now().Add(24 * 30 * time.Hour),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA: true,
	}

	clientCaBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &caPriv.PublicKey, caPriv)
	if err != nil {
		return nil, tls.Certificate{}, err
	}

	clientCa, err := x509.ParseCertificate(clientCaBytes)
	if err != nil {
		return nil, tls.Certificate{}, err
	}

	clientPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, tls.Certificate{}, err
	}

	template = x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Client Cert",
		},
		NotBefore: time.Now().Add(-24 * time.Hour),
		NotAfter:  time.Now().Add(24 * 30 * time.Hour),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA: false,
	}

	clientCertBytes, err := x509.CreateCertificate(rand.Reader, &template, clientCa, &clientPriv.PublicKey, caPriv)
	if err != nil {
		return nil, tls.Certificate{}, err
	}

	clientCert, err := x509.ParseCertificate(clientCaBytes)
	if err != nil {
		return nil, tls.Certificate{}, err
	}

	return clientCa, tls.Certificate{
		Certificate: [][]byte{clientCertBytes},
		PrivateKey:  clientPriv,
		Leaf:        clientCert,
	}, nil

}

func tryBootstrap(rpcPrivKeyBytes []byte) error {
	marshaller := &jsonpb.Marshaler{}
	request, err := marshaller.MarshalToString(&vssmpb.BootstrapRequest{
		RpcPrivateKey: rpcPrivKeyBytes,
	})
	if err != nil {
		return err
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	c := &http.Client{Transport: tr}

	response, err := c.Post("https://localhost:8080/REST/v1/admin/bootstrap", "application/json", strings.NewReader(request))
	if err != nil {
		return err
	}
	var responseMsg vssmpb.BootstrapResponse
	err = jsonpb.Unmarshal(response.Body, &responseMsg)
	if err != nil {
		return err
	}

	return nil
}

type vssmClient struct {
	clientCert    tls.Certificate
	rpcServerCert *x509.Certificate
}

func (c *vssmClient) doRequest(url string, request proto.Message, response proto.Message) error {
	marshaller := &jsonpb.Marshaler{}
	requestStr, err := marshaller.MarshalToString(request)
	if err != nil {
		return err
	}

	trustPool := x509.NewCertPool()
	trustPool.AddCert(c.rpcServerCert)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:      trustPool,
			Certificates: []tls.Certificate{c.clientCert},
			ServerName:   "VSSM",
		},
	}
	httpClient := &http.Client{Transport: tr}

	res, err := httpClient.Post(url, "application/json", strings.NewReader(requestStr))
	if err != nil {
		return err
	}
	if res.StatusCode != 200 {
		return fmt.Errorf("Got non-200 status code: %d", res.StatusCode)
	}
	err = jsonpb.Unmarshal(res.Body, response)
	if err != nil {
		return err
	}

	return nil
}

func TestVssmService(t *testing.T) {

	tlsCert, err := generateSelfSigned()
	if err != nil {
		t.Fatal(err)
	}
	rpcPrivKeyBytes, err := rsa2pkcs8(tlsCert.PrivateKey.(*rsa.PrivateKey))
	if err != nil {
		t.Fatal(err)
	}

	clientCa, clientCert, err := generateClientCaAndCert()
	if err != nil {
		t.Fatal(err)
	}

	clientTrustStore := x509.NewCertPool()
	clientTrustStore.AddCert(clientCa)
	appState := &appState{
		logger: &stubLogger{},
		status: STATUS_BOOTSTRAPPING,
		rpcCertificate: tls.Certificate{
			Certificate: tlsCert.Certificate,
			Leaf:        tlsCert.Leaf,
		},
		clientTrustStore: clientTrustStore,
		rootPassword:     calcScrypt("adminPassword"),
		keyStore: &keyStore{
			symmetricKeys:  make(map[string]*SymmetricKey),
			asymmetricKeys: make(map[string]*AsymmetricKey),
			macKeys:        make(map[string]*MacKey),
		},
		cloudProvider: &localCloudProvider{},
	}

	var server *vssmService
	// The server blocks init until it is bootstrapped, start it in a goroutine
	go func() {
		server = vssmInit(appState)
	}()

	threshold := time.Now().Add(30 * time.Second)
	for {
		if time.Now().After(threshold) {
			t.Fatal("Failed to bootstrap in alloted time.")
		}

		err := tryBootstrap(rpcPrivKeyBytes)
		if err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	defer server.ShutdownNow()

	c := vssmClient{
		clientCert:    clientCert,
		rpcServerCert: tlsCert.Leaf,
	}

	var genKeyResponse vssmpb.GenerateKeyResponse
	err = c.doRequest("https://localhost:8080/REST/v1/admin/generatekey", &vssmpb.GenerateKeyRequest{
		AdminPassword: "adminPassword",
		KeyName:       "foo",
		KeyType:       "SYMMETRIC",
		KeySize:       32,
	}, &genKeyResponse)
	if err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("Super secret thing goes here")
	var encryptResponse vssmpb.SymmetricEncryptResponse
	err = c.doRequest("https://localhost:8080/REST/v1/symmetric/encrypt", &vssmpb.SymmetricEncryptRequest{
		Input:     plaintext,
		KeyName:   "foo",
		Algorithm: "AES/GCM/NoPadding",
	}, &encryptResponse)
	if err != nil {
		t.Fatal(err)
	}

	ciphertext := encryptResponse.Output
	var decryptResponse vssmpb.SymmetricDecryptResponse
	err = c.doRequest("https://localhost:8080/REST/v1/symmetric/decrypt", &vssmpb.SymmetricDecryptRequest{
		Input:     ciphertext,
		KeyName:   "foo",
		Algorithm: "AES/GCM/NoPadding",
	}, &decryptResponse)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(plaintext, decryptResponse.Output) {
		t.Fatal("Got incorrect decrypt response.")
	}
}
