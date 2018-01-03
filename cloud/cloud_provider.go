package cloud

type CloudProvider interface {
	GetPeers() ([]string, error)
	GetAttestation() ([]byte, error)
	VerifyAttestation(attestation []byte) error
}
