package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"os"
	"stash.corp.netflix.com/ps/vssm/awsprov"
	"stash.corp.netflix.com/ps/vssm/cloud"
	"stash.corp.netflix.com/ps/vssm/logging"
)

func main() {

	logger := logging.New(logging.DEBUG, logging.INFO)
	appState := &appState{
		logger: logger,
		status: STATUS_BOOTSTRAPPING,
		keyStore: &keyStore{
			symmetricKeys:  make(map[string]*SymmetricKey),
			asymmetricKeys: make(map[string]*AsymmetricKey),
			macKeys:        make(map[string]*MacKey),
		},
	}

	var cloudProvider cloud.CloudProvider
	if len(os.Args) > 1 && os.Args[1] == "--dev" {
		cloudProvider = &localCloudProvider{}
	} else {
		var err error
		cloudProvider, err = awsprov.New()
		if err != nil {
			logger.Fatal("Unable to initialize AWS cloud provider: %v", err)
			return
		}
	}
	appState.cloudProvider = cloudProvider

	var configBytes []byte
	if _, err := os.Stat("config.json"); err == nil {
		configBytes, err = ioutil.ReadFile("config.json")
		if err != nil {
			logger.Fatal("Error reading config.json: %v", err)
			return
		}
	} else {
		if _, err := os.Stat("/etc/vssm/config.json"); err == nil {
			configBytes, err = ioutil.ReadFile("/etc/vssm/config.json")
			if err != nil {
				logger.Fatal("Error reading config.json: %v", err)
				return
			}
		} else {
			logger.Fatal("Unable to find config.json to load.")
			return
		}
	}
	var config map[string]interface{}
	err := json.Unmarshal(configBytes, &config)
	if err != nil {
		logger.Fatal("Unable to parse config.json: %v", err)
		return
	}

	rpcCertBytes, err := base64.StdEncoding.DecodeString(config["rpcCertificate"].(string))
	if err != nil {
		logger.Fatal("Unable to decode rpc certificate: %v", err)
		return
	}
	rpcCert, err := x509.ParseCertificate(rpcCertBytes)
	if err != nil {
		logger.Fatal("Unable to parse rpc certificate: %v", err)
		return
	}
	appState.rpcCertificate = tls.Certificate{
		Certificate: [][]byte{rpcCertBytes},
		Leaf:        rpcCert,
	}
	appState.clientTrustStore = x509.NewCertPool()
	appState.rootPassword = config["rootPassword"].(string)

	for _, certIface := range config["clientTrustStore"].([]interface{}) {
		certBytes, err := base64.StdEncoding.DecodeString(certIface.(string))
		if err != nil {
			logger.Fatal("Unable to parse client trust store: %v", err)
			return
		}
		cert, err := x509.ParseCertificate(certBytes)
		if err != nil {
			logger.Fatal("Unable to parse client trust store: %v", err)
			return
		}
		appState.clientTrustStore.AddCert(cert)
	}

	service := vssmInit(appState)
	service.WaitForShutdown()
}
