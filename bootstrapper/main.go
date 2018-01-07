package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"github.com/golang/protobuf/jsonpb"
	"io/ioutil"
	"net/http"
	"os"
	"stash.corp.netflix.com/ps/vssm/awsprov"
	"stash.corp.netflix.com/ps/vssm/vssmpb"
)

func writeError(response http.ResponseWriter, err error) {
	response.WriteHeader(500)
	marshaller := jsonpb.Marshaler{}
	marshaller.Marshal(response, &vssmpb.ErrorResponse{
		Error: err.Error(),
	})
}

func loadConfig() (map[string]interface{}, error) {
	var configBytes []byte
	if _, err := os.Stat("config.json"); err == nil {
		configBytes, err = ioutil.ReadFile("config.json")
		if err != nil {
			return nil, fmt.Errorf("Error reading config.json: %v", err)
		}
	} else {
		if _, err := os.Stat("/etc/vssm/config.json"); err == nil {
			configBytes, err = ioutil.ReadFile("/etc/vssm/config.json")
			if err != nil {
				return nil, fmt.Errorf("Error reading config.json: %v", err)
			}
		} else {
			return nil, fmt.Errorf("Unable to find config.json to load.")
		}
	}
	var config map[string]interface{}
	err := json.Unmarshal(configBytes, &config)
	if err != nil {
		return nil, fmt.Errorf("Unable to parse config.json: %v", err)
	}
	return config, nil
}

func readPrivateKey(privKeyPath string) ([]byte, interface{}, error) {
	privKeyPem, err := ioutil.ReadFile(privKeyPath)
	if err != nil {
		return nil, nil, err
	}
	block, _ := pem.Decode(privKeyPem)
	if block == nil {
		return nil, nil, fmt.Errorf("Could not parse private key file; no PEM blocks found.")
	}
	if block.Type != "PRIVATE KEY" {
		return nil, nil, fmt.Errorf("Error parsing private key file, not a private key: %s\n", block.Type)
	}

	privKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, nil, err
	}

	return block.Bytes, privKey, nil
}

func main() {
	flagSet := flag.NewFlagSet("bootstrapper", flag.ContinueOnError)
	expectedAmi := flagSet.String("amiName", "", "Name of trusted AMI.")
	privKeyPath := flagSet.String("privateKey", "", "Private key of VSSM service certificate.")

	err := flagSet.Parse(os.Args[1:])
	if err != nil {
		fmt.Printf("Error parsing flags: %v\n", err)
		return
	}

	if *expectedAmi == "" {
		fmt.Printf("The amiName parameter is required.\n")
		return
	}
	if *privKeyPath == "" {
		fmt.Printf("The privateKey parameter is required.\n")
		return
	}

	privKeyBytes, privKey, err := readPrivateKey(*privKeyPath)
	if err != nil {
		fmt.Printf("Error reading private key file: %v\n", err)
		return
	}

	config, err := loadConfig()
	if err != nil {
		fmt.Printf("Error loading config.json: %v\n", err)
		return
	}

	var rpcCertificate *x509.Certificate
	if cert, ok := config["rpcCertificate"]; !ok {
		fmt.Printf("rpcCertificate missing from config.\n")
		return
	} else {
		certBytes, err := base64.StdEncoding.DecodeString(cert.(string))
		if err != nil {
			fmt.Printf("Could not decode rpcCertificate from config: %v\n", err)
			return
		}
		rpcCertificate, err = x509.ParseCertificate(certBytes)
		if err != nil {
			fmt.Printf("Could not decode rpcCertificate from config: %v\n", err)
			return
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/REST/v1/internal/bootstrapslave", func(response http.ResponseWriter, request *http.Request) {
		var req vssmpb.BootstrapSlaveRequest
		err := jsonpb.Unmarshal(request.Body, &req)
		if err != nil {
			writeError(response, err)
			return
		}

		clientMetadata, err := awsprov.VerifyAndReturnMetadata(req.Attestation)
		if err != nil {
			writeError(response, err)
			return
		}

		clientImageId := clientMetadata["imageId"].(string)
		fmt.Printf("Received bootstrap request from %s\n", clientImageId)
		if clientImageId != *expectedAmi {
			writeError(response, fmt.Errorf("Client image id %s doesn't match instance image id %s", clientImageId, *expectedAmi))
			return
		}

		marshaller := jsonpb.Marshaler{}
		err = marshaller.Marshal(response, &vssmpb.BootstrapSlaveResponse{
			RpcPrivateKey: privKeyBytes,
		})
		if err != nil {
			fmt.Printf("Error marshalling response: %v\n", err)
		}
	})

	internalUnauthServer := &http.Server{
		Addr:    ":8083",
		Handler: mux,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{{
				Certificate: [][]byte{rpcCertificate.Raw},
				PrivateKey:  privKey,
				Leaf:        rpcCertificate,
			}},
			ClientAuth: tls.NoClientCert,
		},
	}
	err = internalUnauthServer.ListenAndServeTLS("", "")
	if err != nil {
		fmt.Printf("Error listening: %v\n", err)
	}
}
