package main

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"github.com/golang/protobuf/jsonpb"
	"github.com/golang/protobuf/proto"
	"golang.org/x/net/context"
	"io/ioutil"
	mathrand "math/rand"
	"net/http"
	"stash.corp.netflix.com/ps/vssm/vssmpb"
	"strings"
	"time"
)

func serviceHandlerFor(requestType func() proto.Message, handler func(context.Context, proto.Message) (proto.Message, error)) func(w http.ResponseWriter, r *http.Request) {
	marshaller := &jsonpb.Marshaler{}
	return func(w http.ResponseWriter, r *http.Request) {
		request := requestType()
		err := jsonpb.Unmarshal(r.Body, request)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			marshaller.Marshal(w, &vssmpb.ErrorResponse{
				Error: err.Error(),
			})
			return
		}
		r.Body.Close()

		response, err := handler(context.Background(), request)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			marshaller.Marshal(w, &vssmpb.ErrorResponse{
				Error: err.Error(),
			})
			return
		}
		marshaller.Marshal(w, response)
	}
}

func vssmInit(appState *appState) {

	var metadataBytes []byte
	if appState.myAmi != "" {
		var err error
		metadataBytes, err = getLocalCms()
		if err != nil {
			appState.logger.Fatal("Unable to get CMS document: %v", err)
			return
		}
	} else {
		metadataBytes = nil
	}

	bootstrapChannel := make(chan bool, 1)
	shutdownChannel := make(chan bool)
	mux := http.NewServeMux()
	mux.HandleFunc("/REST/v1/admin/bootstrap", func(w http.ResponseWriter, r *http.Request) {
		marshaller := &jsonpb.Marshaler{}
		request := vssmpb.BootstrapRequest{}
		err := jsonpb.Unmarshal(r.Body, &request)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			marshaller.Marshal(w, &vssmpb.ErrorResponse{
				Error: err.Error(),
			})
			return
		}
		r.Body.Close()

		var key interface{}
		if key, err = x509.ParsePKCS8PrivateKey(request.RpcPrivateKey); err == nil {
			switch key := key.(type) {
			case *rsa.PrivateKey, *ecdsa.PrivateKey:
				appState.rpcPrivateKeyPkcs8 = request.RpcPrivateKey
				appState.rpcCertificate.PrivateKey = key
				appState.logger.Info("Manual bootstrap successful...")
				bootstrapChannel <- true
			default:
				appState.logger.Error("tls: found unknown private key type in PKCS#8 wrapping")
			}
		}

		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			marshaller.Marshal(w, &vssmpb.ErrorResponse{
				Error: err.Error(),
			})
			return
		}
		marshaller.Marshal(w, &vssmpb.BootstrapResponse{})
	})
	bootstrapCert, err := generateSelfSigned()
	if err != nil {
		appState.logger.Fatal("Unable to generate self-signed certificate for bootstrapping: %s", err)
		return
	}
	s := &http.Server{
		Addr:    ":8080",
		Handler: mux,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{bootstrapCert},
			ClientAuth:   tls.NoClientCert,
		},
	}
	go func() {
		err := s.ListenAndServeTLS("", "")
		if err != nil {
			if err != http.ErrServerClosed {
				appState.logger.Error("Error listening: %v", err)
			}
		}
		shutdownChannel <- true
	}()

	appState.logger.Info("Attempting bootstrap...")

	done := false
	doBootstrapWork := func() {
		if appState.rpcCertificate.PrivateKey == nil {
			_attemptBootstrap(appState, metadataBytes)
		}

		if appState.rpcCertificate.PrivateKey != nil {
			err := _synchronizeNow(appState)
			if err != nil {
				appState.logger.Error("Error performing initial synchronization: %v", err)
			} else {
				appState.logger.Info("Initial synchronization successful...")
				done = true
			}
		}
	}

	ticker := time.NewTicker(30 * time.Second)
	doBootstrapWork()
	for !done {
		select {
		case <-ticker.C:
			doBootstrapWork()
		case <-bootstrapChannel:
			done = true
		}
	}

	ticker.Stop()
	s.Shutdown(context.Background())
	<-shutdownChannel
	startApp(appState)
}

func _chooseRandomPeer(appState *appState) (string, error) {
	peers, err := GetPeers(appState.myRegion, appState.myAsg)
	if err != nil {
		return "", err
	}
	// Choose a random peer (that isn't myself)
	if len(peers) == 0 || (len(peers) == 1 && peers[0] == appState.myIp) {
		return "", errors.New("No peers found.")
	}

	peer := appState.myIp
	for peer == appState.myIp {
		n := mathrand.Int31n(int32(len(peers)))
		peer = peers[n]
	}
	return peer, nil
}

func _attemptBootstrap(appState *appState, metadataBytes []byte) {

	peers, err := GetPeers(appState.myRegion, appState.myAsg)
	if err != nil {
		appState.logger.Error("Unable to get a peers for bootstrapping: %v", err)
		return
	}

	marshaller := &jsonpb.Marshaler{}
	request := &vssmpb.BootstrapSlaveRequest{
		ClientCms: metadataBytes,
	}
	requestStr, err := marshaller.MarshalToString(request)
	if err != nil {
		appState.logger.Error("Unable to build bootstrap request string: %v", err)
		return
	}

	trustStore := x509.NewCertPool()
	trustStore.AddCert(appState.rpcCertificate.Leaf)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    trustStore,
				ServerName: "VSSM",
			},
		},
	}

	for _, peer := range peers {
		if peer == appState.myIp {
			continue
		}

		appState.logger.Info("Attempting to bootstrap from %s...", peer)

		response, err := client.Post("https://"+peer+":8083/REST/v1/internal/bootstrapslave", "application/json",
			strings.NewReader(requestStr))
		if err != nil {
			appState.logger.Error("Error performing automatic bootstrap: %s", err)
		} else {
			if response.StatusCode != 200 {
				appState.logger.Error("Got non-200 status code during automatic bootstrap: %s", response.Status)
				body, err := ioutil.ReadAll(response.Body)
				response.Body.Close()
				if err == nil {
					appState.logger.Error("Response body: %s", string(body))
				}
			} else {
				var responseMsg vssmpb.BootstrapSlaveResponse
				err = jsonpb.Unmarshal(response.Body, &responseMsg)
				response.Body.Close()
				if err != nil {
					appState.logger.Error("Unable to unmarshal response: %v", err)
				} else {
					if key, err := x509.ParsePKCS8PrivateKey(responseMsg.RpcPrivateKey); err == nil {
						switch key := key.(type) {
						case *rsa.PrivateKey, *ecdsa.PrivateKey:
							appState.rpcPrivateKeyPkcs8 = responseMsg.RpcPrivateKey
							appState.rpcCertificate.PrivateKey = key
							appState.logger.Info("Automatic bootstrap successful...")
						default:
							appState.logger.Error("tls: found unknown private key type in PKCS#8 wrapping")
						}
					}
				}
			}
		}
	}
}

func _synchronizeNow(appState *appState) error {
	appState.logger.Debug("Attempting synchronization...")

	peer, err := _chooseRandomPeer(appState)
	if err != nil {
		return err
	}

	appState.logger.Debug("Request synchronization from %s...", peer)

	marshaller := &jsonpb.Marshaler{}
	request := &vssmpb.SynchronizeStateRequest{}
	requestStr, err := marshaller.MarshalToString(request)
	if err != nil {
		return err
	}

	trustStore := x509.NewCertPool()
	trustStore.AddCert(appState.rpcCertificate.Leaf)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{appState.rpcCertificate},
				RootCAs:      trustStore,
				ServerName:   "VSSM",
			},
		},
	}

	response, err := client.Post("https://"+peer+":8082/REST/v1/internal/synchronizestate", "application/json",
		strings.NewReader(requestStr))
	if err != nil {
		return err
	}
	if response.StatusCode != 200 {
		return fmt.Errorf("Bad status code: %d", response.StatusCode)
	}

	var responseMsg vssmpb.SynchronizeStateResponse
	err = jsonpb.Unmarshal(response.Body, &responseMsg)
	response.Body.Close()
	if err != nil {
		return err
	} else {
		err = synchronizeStateFromResponse(appState, &responseMsg)
		if err != nil {
			return err
		}
	}
	return nil
}

func synchronizeStateFromResponse(appState *appState, responseMsg *vssmpb.SynchronizeStateResponse) error {
	{
		newMap := make(map[string]*SymmetricKey)
		for name, key := range appState.keyStore.symmetricKeys {
			newMap[name] = key
		}
		for _, key := range responseMsg.SymmetricKey {
			remoteModified := timeOfUnixMillis(key.CreatedAt)
			if _, exists := newMap[key.Name]; !exists || newMap[key.Name].createdAt.Before(remoteModified) {
				appState.logger.Info("New symmetric key added from synchronization message: %s", key.Name)
				newMap[key.Name] = &SymmetricKey{
					key:       key.Key,
					createdAt: remoteModified,
				}
			}
		}
		appState.keyStore.symmetricKeys = newMap
	}
	{
		newMap := make(map[string]*AsymmetricKey)
		for name, key := range appState.keyStore.asymmetricKeys {
			newMap[name] = key
		}
		for _, key := range responseMsg.AsymmetricKey {
			remoteModified := timeOfUnixMillis(key.CreatedAt)
			if _, exists := newMap[key.Name]; !exists || newMap[key.Name].createdAt.Before(remoteModified) {
				appState.logger.Info("New asymmetric key added from synchronization message: %s", key.Name)
				privateKey, err := x509.ParsePKCS8PrivateKey(key.Key)
				if err == nil {
					newMap[key.Name] = &AsymmetricKey{
						key:        privateKey,
						pkcs8Bytes: key.Key,
						keyType:    key.KeyType,
						createdAt:  remoteModified,
					}
				}
			}
		}
		appState.keyStore.asymmetricKeys = newMap
	}
	{
		newMap := make(map[string]*MacKey)
		for name, key := range appState.keyStore.macKeys {
			newMap[name] = key
		}
		for _, key := range responseMsg.MacKey {
			remoteModified := timeOfUnixMillis(key.CreatedAt)
			if _, exists := newMap[key.Name]; !exists || newMap[key.Name].createdAt.Before(remoteModified) {
				appState.logger.Info("New mac key added from synchronization message: %s", key.Name)
				newMap[key.Name] = &MacKey{
					key:       key.Key,
					createdAt: time.Unix(key.CreatedAt/1000, (key.CreatedAt%1000)*1e6),
				}
			}
		}
		appState.keyStore.macKeys = newMap
	}

	return nil
}

func pushSyncNow(appState *appState) error {
	peerIps, err := GetPeers(appState.myRegion, appState.myAsg)
	if err != nil {
		return err
	}
	for _, ip := range peerIps {
		if ip == appState.myIp {
			continue
		}

		appState.logger.Info("Pushing state synchronization to %s.", ip)

		marshaller := &jsonpb.Marshaler{}
		request := &vssmpb.SynchronizeStatePushRequest{
			SynchronizeStateMessage: appStateToSynchronizeMessage(appState),
		}

		requestStr, err := marshaller.MarshalToString(request)
		if err != nil {
			return err
		}

		trustStore := x509.NewCertPool()
		trustStore.AddCert(appState.rpcCertificate.Leaf)

		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					Certificates: []tls.Certificate{appState.rpcCertificate},
					RootCAs:      trustStore,
					ServerName:   "VSSM",
				},
			},
		}

		response, err := client.Post("https://"+ip+":8082/REST/v1/internal/synchronizestatepush", "application/json",
			strings.NewReader(requestStr))
		if err != nil {
			appState.logger.Error("Failed to push synchronization: %s", err)
			continue
		}
		if response.StatusCode != 200 {
			appState.logger.Error("Failed to push synchronization, bad status: %s", response.Status)
			continue
		}

		var responseMsg vssmpb.SynchronizeStatePushResponse
		err = jsonpb.Unmarshal(response.Body, &responseMsg)
		response.Body.Close()
		if err != nil {
			appState.logger.Error("Failed to parse push synchronization response: %s", err)
			continue
		} else {
			// Do nothing with the response; presentl it is empty
		}
	}

	return nil
}

func startApp(appState *appState) {

	appState.logger.Info("Entering normal application running state...")
	shutdownChannel := make(chan bool)

	var internalSvc vssmpb.InternalServiceServer
	internalSvc = &InternalServiceImpl{appState}

	var service vssmpb.VssmServiceServer
	service = &VssmServiceImpl{appState}

	var adminSvc vssmpb.AdminServiceServer
	adminSvc = &AdminServiceImpl{appState}

	mux := http.NewServeMux()
	mux.HandleFunc("/REST/v1/internal/bootstrapslave", serviceHandlerFor(
		func() proto.Message { return &vssmpb.BootstrapSlaveRequest{} },
		func(context context.Context, request proto.Message) (proto.Message, error) {
			return internalSvc.BootstrapSlave(context, request.(*vssmpb.BootstrapSlaveRequest))
		}))

	internalCertPool := x509.NewCertPool()
	internalCertPool.AddCert(appState.rpcCertificate.Leaf)
	internalUnauthServer := &http.Server{
		Addr:    ":8083",
		Handler: mux,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{appState.rpcCertificate},
			ClientAuth:   tls.NoClientCert,
		},
	}
	go func() {
		err := internalUnauthServer.ListenAndServeTLS("", "")
		if err != nil {
			appState.logger.Error("Error listening: %v", err)
		}
		shutdownChannel <- true
	}()

	mux = http.NewServeMux()
	mux.HandleFunc("/REST/v1/internal/synchronizestate", serviceHandlerFor(
		func() proto.Message { return &vssmpb.SynchronizeStateRequest{} },
		func(context context.Context, request proto.Message) (proto.Message, error) {
			return internalSvc.SynchronizeState(context, request.(*vssmpb.SynchronizeStateRequest))
		}))
	mux.HandleFunc("/REST/v1/internal/synchronizestatepush", serviceHandlerFor(
		func() proto.Message { return &vssmpb.SynchronizeStatePushRequest{} },
		func(context context.Context, request proto.Message) (proto.Message, error) {
			return internalSvc.SynchronizeStatePush(context, request.(*vssmpb.SynchronizeStatePushRequest))
		}))

	internalAuthServer := &http.Server{
		Addr:    ":8082",
		Handler: mux,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{appState.rpcCertificate},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    internalCertPool,
		},
	}
	go func() {
		err := internalAuthServer.ListenAndServeTLS("", "")
		if err != nil {
			appState.logger.Error("Error listening: %v", err)
		}
		shutdownChannel <- true
	}()

	mux = http.NewServeMux()
	mux.HandleFunc("/REST/v1/symmetric/encrypt", serviceHandlerFor(
		func() proto.Message { return &vssmpb.SymmetricEncryptRequest{} },
		func(context context.Context, request proto.Message) (proto.Message, error) {
			return service.SymmetricEncrypt(context, request.(*vssmpb.SymmetricEncryptRequest))
		}))
	mux.HandleFunc("/REST/v1/symmetric/decrypt", serviceHandlerFor(
		func() proto.Message { return &vssmpb.SymmetricDecryptRequest{} },
		func(context context.Context, request proto.Message) (proto.Message, error) {
			return service.SymmetricDecrypt(context, request.(*vssmpb.SymmetricDecryptRequest))
		}))
	mux.HandleFunc("/REST/v1/asymmetric/encrypt", serviceHandlerFor(
		func() proto.Message { return &vssmpb.AsymmetricEncryptRequest{} },
		func(context context.Context, request proto.Message) (proto.Message, error) {
			return service.AsymmetricEncrypt(context, request.(*vssmpb.AsymmetricEncryptRequest))
		}))
	mux.HandleFunc("/REST/v1/asymmetric/decrypt", serviceHandlerFor(
		func() proto.Message { return &vssmpb.AsymmetricDecryptRequest{} },
		func(context context.Context, request proto.Message) (proto.Message, error) {
			return service.AsymmetricDecrypt(context, request.(*vssmpb.AsymmetricDecryptRequest))
		}))
	mux.HandleFunc("/REST/v1/asymmetric/sign", serviceHandlerFor(
		func() proto.Message { return &vssmpb.AsymmetricSignRequest{} },
		func(context context.Context, request proto.Message) (proto.Message, error) {
			return service.AsymmetricSign(context, request.(*vssmpb.AsymmetricSignRequest))
		}))
	mux.HandleFunc("/REST/v1/asymmetric/verify", serviceHandlerFor(
		func() proto.Message { return &vssmpb.AsymmetricVerifyRequest{} },
		func(context context.Context, request proto.Message) (proto.Message, error) {
			return service.AsymmetricVerify(context, request.(*vssmpb.AsymmetricVerifyRequest))
		}))
	mux.HandleFunc("/REST/v1/hmac/create", serviceHandlerFor(
		func() proto.Message { return &vssmpb.HmacCreateRequest{} },
		func(context context.Context, request proto.Message) (proto.Message, error) {
			return service.HmacCreate(context, request.(*vssmpb.HmacCreateRequest))
		}))
	mux.HandleFunc("/REST/v1/hmac/verify", serviceHandlerFor(
		func() proto.Message { return &vssmpb.HmacVerifyRequest{} },
		func(context context.Context, request proto.Message) (proto.Message, error) {
			return service.HmacVerify(context, request.(*vssmpb.HmacVerifyRequest))
		}))

	mux.HandleFunc("/REST/v1/admin/generatekey", serviceHandlerFor(
		func() proto.Message { return &vssmpb.GenerateKeyRequest{} },
		func(context context.Context, request proto.Message) (proto.Message, error) {
			return adminSvc.GenerateKey(context, request.(*vssmpb.GenerateKeyRequest))
		}))
	mux.HandleFunc("/REST/v1/admin/injectkey", serviceHandlerFor(
		func() proto.Message { return &vssmpb.InjectKeyRequest{} },
		func(context context.Context, request proto.Message) (proto.Message, error) {
			return adminSvc.InjectKey(context, request.(*vssmpb.InjectKeyRequest))
		}))
	mux.HandleFunc("/REST/v1/admin/generatebackup", serviceHandlerFor(
		func() proto.Message { return &vssmpb.GenerateBackupRequest{} },
		func(context context.Context, request proto.Message) (proto.Message, error) {
			return adminSvc.GenerateBackup(context, request.(*vssmpb.GenerateBackupRequest))
		}))
	mux.HandleFunc("/REST/v1/admin/restorebackup", serviceHandlerFor(
		func() proto.Message { return &vssmpb.RestoreBackupRequest{} },
		func(context context.Context, request proto.Message) (proto.Message, error) {
			return adminSvc.RestoreBackup(context, request.(*vssmpb.RestoreBackupRequest))
		}))
	mux.HandleFunc("/REST/v1/admin/listkeys", serviceHandlerFor(
		func() proto.Message { return &vssmpb.ListKeysRequest{} },
		func(context context.Context, request proto.Message) (proto.Message, error) {
			return adminSvc.ListKeys(context, request.(*vssmpb.ListKeysRequest))
		}))
	mux.HandleFunc("/REST/v1/admin/getlogs", serviceHandlerFor(
		func() proto.Message { return &vssmpb.GetLogsRequest{} },
		func(context context.Context, request proto.Message) (proto.Message, error) {
			return adminSvc.GetLogs(context, request.(*vssmpb.GetLogsRequest))
		}))

	server := &http.Server{
		Addr:    ":8080",
		Handler: mux,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{appState.rpcCertificate},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    appState.clientTrustStore,
		},
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}
	go func() {
		err := server.ListenAndServeTLS("", "")
		if err != nil {
			appState.logger.Error("Error listening: %v", err)
		}
		shutdownChannel <- true
	}()

	go func() {
		for true {
			err := _synchronizeNow(appState)
			if err != nil {
				appState.logger.Error("Error during synchronization: %v", err)
			}
			time.Sleep(5 * time.Minute)
			time.Sleep((time.Duration)(mathrand.Int63n(300)) * time.Second)
		}
	}()

	appState.status = STATUS_RUNNING

	<-shutdownChannel
	<-shutdownChannel
}
