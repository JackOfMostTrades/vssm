package main

import (
	"golang.org/x/net/context"
	"stash.corp.netflix.com/ps/vssm/vssmpb"
)

type InternalServiceImpl struct {
	appState *appState
}

func (s *InternalServiceImpl) BootstrapSlave(ctx context.Context, request *vssmpb.BootstrapSlaveRequest) (*vssmpb.BootstrapSlaveResponse, error) {
	err := s.appState.cloudProvider.VerifyAttestation(request.Attestation)
	if err != nil {
		return nil, err
	}

	return &vssmpb.BootstrapSlaveResponse{
		RpcPrivateKey: s.appState.rpcPrivateKeyPkcs8,
	}, nil
}

func (s *InternalServiceImpl) SynchronizeState(ctx context.Context, request *vssmpb.SynchronizeStateRequest) (*vssmpb.SynchronizeStateResponse, error) {
	response := appStateToSynchronizeMessage(s.appState)
	return response, nil
}

func appStateToSynchronizeMessage(appState *appState) *vssmpb.SynchronizeStateResponse {
	response := &vssmpb.SynchronizeStateResponse{}
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
