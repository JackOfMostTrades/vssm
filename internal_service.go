package main

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/fullsailor/pkcs7"
	"golang.org/x/net/context"
	"stash.corp.netflix.com/ps/vssm/vssmpb"
)

type InternalServiceImpl struct {
	appState *appState
}

func (s *InternalServiceImpl) BootstrapSlave(ctx context.Context, request *vssmpb.BootstrapSlaveRequest) (*vssmpb.BootstrapSlaveResponse, error) {

	s.appState.logger.Debug("ClientCms=%s", base64.StdEncoding.EncodeToString(request.ClientCms))

	p7, err := pkcs7.Parse(request.ClientCms)
	if err != nil {
		return nil, err
	}

	var clientMetadata map[string]interface{}
	err = json.Unmarshal(p7.Content, &clientMetadata)
	if err != nil {
		return nil, err
	}

	region := clientMetadata["region"].(string)
	certBytes, err := base64.StdEncoding.DecodeString(AWS_CERTS[region])
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, err
	}

	p7.Certificates = []*x509.Certificate{cert}
	err = p7.Verify()
	if err != nil {
		return nil, err
	}

	clientImageId := clientMetadata["imageId"].(string)
	if clientImageId != s.appState.myAmi {
		return nil, fmt.Errorf("Client image id %s doesn't match instance image id %s", clientImageId, s.appState.myAmi)
	}

	return &vssmpb.BootstrapSlaveResponse{
		RpcPrivateKey: s.appState.rpcPrivateKeyPkcs8,
	}, nil
}

func (s *InternalServiceImpl) SynchronizeState(ctx context.Context, request *vssmpb.SynchronizeStateRequest) (*vssmpb.SynchronizeStateResponse, error) {
	alreadyKnown := false
	for _, client := range s.appState.knownClients {
		if client == request.ClientIp {
			alreadyKnown = true
			break
		}
	}
	if !alreadyKnown {
		s.appState.knownClients = append(s.appState.knownClients, request.ClientIp)
	}

	response := appStateToSynchronizeMessage(s.appState)

	return response, nil
}

func appStateToSynchronizeMessage(appState *appState) *vssmpb.SynchronizeStateResponse {
	response := &vssmpb.SynchronizeStateResponse{}
	response.KnownClients = appState.knownClients
	for name, key := range appState.keyStore.symmetricKeys {
		response.SymmetricKey = append(response.SymmetricKey, &vssmpb.SymmetricKey{
			Name:      name,
			CreatedAt: key.createdAt.UnixNano() / 1e6,
			Key:       key.key,
		})
	}
	for name, key := range appState.keyStore.asymmetricKeys {
		response.AsymmetricKey = append(response.AsymmetricKey, &vssmpb.AsymmetricKey{
			Name:      name,
			KeyType:   key.keyType,
			CreatedAt: key.createdAt.UnixNano() / 1e6,
			Key:       key.pkcs8Bytes,
		})
	}
	for name, key := range appState.keyStore.macKeys {
		response.MacKey = append(response.MacKey, &vssmpb.MacKey{
			Name:      name,
			CreatedAt: key.createdAt.UnixNano() / 1e6,
			Key:       key.key,
		})
	}
	return response
}

func (s *InternalServiceImpl) SynchronizeStatePush(ctx context.Context, request *vssmpb.SynchronizeStatePushRequest) (*vssmpb.SynchronizeStatePushResponse, error) {
	s.appState.logger.Info("Received state synchronization push.")
	err := synchronizeStateFromResponse(s.appState, request.SynchronizeStateMessage)
	if err != nil {
		return nil, err
	}
	return &vssmpb.SynchronizeStatePushResponse{}, nil
}
