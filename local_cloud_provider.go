package main

import "errors"

type localCloudProvider struct{}

func (p *localCloudProvider) GetPeers() ([]string, error) {
	return nil, nil
}
func (p *localCloudProvider) GetAttestation() ([]byte, error) {
	return nil, nil
}
func (p *localCloudProvider) VerifyAttestation(attestation []byte) error {
	return errors.New("Attestation cannot be performed for localhost.")
}
