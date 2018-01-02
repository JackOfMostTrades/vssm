package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"stash.corp.netflix.com/ps/vssm/logging"
	"time"
)

type AppStatus int

const (
	STATUS_BOOTSTRAPPING = iota
	STATUS_RUNNING
)

type appState struct {
	logger             logging.Logger
	status             AppStatus
	rpcPrivateKeyPkcs8 []byte
	rpcCertificate     tls.Certificate
	clientTrustStore   *x509.CertPool
	rootPassword       string
	keyStore           *keyStore

	// Instance metadata
	myIp     string
	myAmi    string
	myAsg    string
	myRegion string
}

func (s *appState) serialize() []byte {
	out, err := json.Marshal(s)
	if err != nil {
		panic(err)
	}
	return out
}
func deserializeAppState(b []byte) *appState {
	s := appState{}
	err := json.Unmarshal(b, &s)
	if err != nil {
		panic(err)
	}
	return &s
}

func timeOfUnixMillis(t int64) time.Time {
	return time.Unix(t/1000, (t%1000)*1e6)
}
func timeToUnixMillis(t time.Time) int64 {
	return t.UnixNano() / 1e6
}
