package scryptlib

import "testing"

func TestCalcAndVerify(t *testing.T) {
	hash := CalcScrypt("foobar")
	if !VerifyScrypt("foobar", hash) {
		t.Error("Verification failed.")
	}
	if VerifyScrypt("foobar2", hash) {
		t.Error("Verification should have failed.")
	}
}

func TestVerifyKnownHash(t *testing.T) {
	hash := "$s0$F0801$XHElFk20jS6fT4yNPCLuFw==$tKUB+oOGEZV3TQSMz8qgHACzavObaS8KFby+VA9IAn8="
	if !VerifyScrypt("password", hash) {
		t.Error("Verification failed.")
	}
}
