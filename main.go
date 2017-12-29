package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/fullsailor/pkcs7"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
)

func main() {

	appState := &appState{
		status: STATUS_BOOTSTRAPPING,
		keyStore: &keyStore{
			symmetricKeys:  make(map[string]*SymmetricKey),
			asymmetricKeys: make(map[string]*AsymmetricKey),
			macKeys:        make(map[string]*MacKey),
		},
	}

	if len(os.Args) > 1 && os.Args[1] == "--dev" {
		appState.myAmi = ""
	} else {
		bytes, err := getLocalCms()
		if err != nil {
			fmt.Printf("Unable to get CMS document: %v\n", err)
			return
		}
		p7, err := pkcs7.Parse(bytes)
		if err != nil {
			fmt.Printf("Unable to parse CMS document: %v\n", err)
			return
		}
		var metadata map[string]interface{}
		err = json.Unmarshal(p7.Content, &metadata)
		if err != nil {
			fmt.Printf("Unable to parse CMS document: %v\n", err)
			return
		}
		appState.myAmi = metadata["imageId"].(string)
	}

	var configBytes []byte
	if _, err := os.Stat("config.json"); err == nil {
		configBytes, err = ioutil.ReadFile("config.json")
		if err != nil {
			fmt.Printf("Error reading config.json: %v\n", err)
			return
		}
	} else {
		if _, err := os.Stat("/etc/vssm/config.json"); err == nil {
			configBytes, err = ioutil.ReadFile("/etc/vssm/config.json")
			if err != nil {
				fmt.Printf("Error reading config.json: %v\n", err)
				return
			}
		} else {
			fmt.Printf("Unable to find config.json to load.")
			return
		}
	}
	var config map[string]interface{}
	err := json.Unmarshal(configBytes, &config)
	if err != nil {
		fmt.Printf("Unable to parse config.json: %v\n", err)
		return
	}

	rpcCertBytes, err := base64.StdEncoding.DecodeString(config["rpcCertificate"].(string))
	if err != nil {
		fmt.Printf("Unable to decode rpc certificate: %v\n", err)
		return
	}
	rpcCert, err := x509.ParseCertificate(rpcCertBytes)
	if err != nil {
		fmt.Printf("Unable to parse rpc certificate: %v\n", err)
		return
	}
	appState.rpcCertificate = tls.Certificate{
		Certificate: [][]byte{rpcCertBytes},
		Leaf:        rpcCert,
	}
	appState.bootstrapHost = config["bootstrapHost"].(string)
	appState.clientTrustStore = x509.NewCertPool()
	appState.rootPassword = config["rootPassword"].(string)

	for _, certIface := range config["clientTrustStore"].([]interface{}) {
		certBytes, err := base64.StdEncoding.DecodeString(certIface.(string))
		if err != nil {
			fmt.Printf("Unable to parse client trust store: %v\n", err)
			return
		}
		cert, err := x509.ParseCertificate(certBytes)
		if err != nil {
			fmt.Printf("Unable to parse client trust store: %v\n", err)
			return
		}
		appState.clientTrustStore.AddCert(cert)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/REST/v1/healthcheck", func(w http.ResponseWriter, r *http.Request) {
		switch appState.status {
		case STATUS_BOOTSTRAPPING:
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write(([]byte)("bootstrapping"))
		case STATUS_RUNNING:
			w.WriteHeader(http.StatusOK)
			w.Write(([]byte)("running"))
		}
	})
	s := &http.Server{
		Addr:    ":8081",
		Handler: mux,
	}
	go func() {
		err := s.ListenAndServe()
		if err != nil {
			fmt.Printf("Error listening: %v\n", err)
		}
	}()

	vssmInit(appState)
}

func getLocalCms() ([]byte, error) {
	response, err := http.Get("http://169.254.169.254/latest/dynamic/instance-identity/rsa2048")
	if err != nil {
		return nil, err
	}
	b64Bytes, err := ioutil.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		return nil, err
	}
	b64Str := strings.Replace((string)(b64Bytes), "\n", "", -1)
	bytes, err := base64.StdEncoding.DecodeString(b64Str)
	if err != nil {
		return nil, err
	}
	return bytes, nil
}
