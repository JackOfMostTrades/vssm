package main

import (
	"bytes"
	"crypto"
	"crypto/elliptic"
	"encoding/base64"
	"fmt"
	"stash.corp.netflix.com/ps/vssm/vssmpb"
	"testing"
)

var testKeyStore *keyStore = &keyStore{
	symmetricKeys: map[string]*SymmetricKey{
		"aes_key": {
			key: randBytes(32),
		},
		"des_key": {
			key: randBytes(8),
		},
		"3des_key": {
			key: randBytes(24),
		},

		"test_aes_key": {
			key: mustBase64Decode("beM1mbmIjvkDzUluKnq4f1PPszKoYRUJrbFvszjDGuw="),
		},
		"test_des_key": {
			key: mustBase64Decode("5P/j6qgySvY="),
		},
		"test_3des_key": {
			key: mustBase64Decode("r6WDe2kjg2mwVRB9znpgeWJEgqhneqeS"),
		},
	},
	asymmetricKeys: map[string]*AsymmetricKey{
		"rsa_2048": generateRsaKey(2048),
		"ec_p256":  generateEcKey(elliptic.P256()),

		"test_rsa_2048": parseAsymmetricKey("MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQD03be7+HAX9EHYHATywhZmGR7CldIjXoXzIMqpBpKCCXQ+cxqzhoFjWUa6ZcXRAUlN4bwJIHONp9bN/r1i7j1I76TMoGNr8gnCTvXhd3DxBqU5q1iq6lC6AsAFinXZFnEx0lKuOsMdB1L9mPlFTD7IzbuK30jOwa4v7hcuYco0TAcD+ZQzKqFTccj0MukcHKggqpSWh6V8Rblxe8CdkO4GcaAmac42UCHz+//hb9j2ZRK4WvMp8pBE70c9q79iwF82LGrTiN7MoVAMHmOA4eJLN2vcGig7M7LGKM9p5joGkTNsfcp2urSmREyPGXT3/iSOgBe4ZK2cHiuaU17wnbAlAgMBAAECggEBAPJoWE8WuGmOXmzB+EgWyjPS5He/9+MZ3UN+kAJaxklDcLeuHZ3iJ08h/3nh7L5nJpmaQhtK6/otUOJnMDezICqHSz9j/GjNmMmqf5HwO3fwmzsHHOU+yCINPOl/VAFQTUkELOPcunGPYaI6gXMP8wu5V9M4DozYgkdizcIV/yZaucUEJ+cj0s7lMw3x3AjLDnf2uxRNne0DkPrx95f7Zt+zWgRwj3HC5Qz4X1X0ZU4vDfXGACcJGl+8AtHDykFGLtfnI0x5nwN7xCC7x53PWMXPdzE1mQEsUyC8aiQZ95jknCvheWpu27XQo8dElg6B0sBJIcotkUhlgeDnK7qt1dUCgYEA/gXOWMhBvXxLG4ophTzRvaEbOqbm3axzVhLdH9s3DqXLruqotv8t+7eFsOgDjPJq0r2yzJxuvvmVyQBKeLyZu+3nWiqJmRXZ0cqNlYq1zEtkhjMtwsvlfdcOzB3v7prSCE0E3/hiTXSrQE8t11EuB06bwyrdynkWTVusA4MR3rcCgYEA9sWqS5ghN3MBqHUsDdrig0uuAZDMt1bqmoWm2lQmDYf+sktvwpqqP7X5vPhj6j56BcBkqWxYb4youALegQPgvcgxYvSWWPIHxp7IIJeliBh78oI5SY37m6aniqPKl5BMxXgYt08T0goiazS1emM3wfuOERcUjDwKQx0dO09EjAMCgYAQXlFomSbbTeoNET8RrdSaEoqNofmYaSdZcYe8KMUIdZiFYeuTNyhAYxgDSUAJUgmeIMkntCDSv4RuWk1yMDz7xh21Sq5pJeZORW4QJ8sFKgqFN0EIn1jfXf8/GeK/Dkzgag4ZXIkBEraCQ1fh2wJLSD5zOgzmohzUyUZxR33cSwKBgQDWG368BAyd7Zz8ql1E0CtEO7+IADh+wlzfISM5v1Uc3GfyDl2zfTpF+P/sI5+dOAPrRZiRHz5D2sjwjxy618CBKVcgQpLILYbtoAqHrMukn4m7SZ2m4hfyXtBzC9XVVxAlLSRUt7m8vapLVfo3bCqOllIXJe1gFx/YR0R7lzUkPQKBgQCtld2rLOGX7OQ/xe735mOeVQWG7PeEtoeNz82d0qqmkAwYdU01cLGBUTjGUuGc5NqoUOzP+NfN1x0UEaXdJzxVm2hikkeJ39CmA8nydSmJFy9EBtGkOwMNFSdmfph87TVEBRq45bxbs8Ahdv6SB/D5sjJfOUFzKRC5d3T6M0Wxxg=="),
		"test_ec_p256":  parseAsymmetricKey("MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg+SD05Hrpzktt3L0bZWs+6VlJxdwXRt/CvFPmrGQVjmChRANCAAT6Aa3odhVDKRbb9A4oru2tS6jUi3HcYGaSrpFYDvmlJOCEzci1eDdYxizrCKQkv3NwfAzFmZDxquoksLpnBCyb"),
	},
	macKeys: map[string]*MacKey{
		"mac_key": {
			key: randBytes(32),
		},
		"test_mac_key": {
			key: mustBase64Decode("1ZzxYa7IxD0LE1gUVRJt71lukK+2WpZ0Ssbue2K4W4w="),
		},
	},
}
var testVssmService *VssmServiceImpl = &VssmServiceImpl{
	appState: &appState{
		logger:   &stubLogger{},
		keyStore: testKeyStore,
	},
}

func TestSymmetricEncryptAndDecrypt(t *testing.T) {
	_testSymmetricEncryptAndDecrypt(t, "aes_key", "AES/ECB/PKCS5Padding")
	_testSymmetricEncryptAndDecrypt(t, "aes_key", "AES/CBC/PKCS5Padding")
	_testSymmetricEncryptAndDecrypt(t, "aes_key", "AES/CTR/PKCS5Padding")
	_testSymmetricEncryptAndDecrypt(t, "aes_key", "AES/CTR/NoPadding")
	_testSymmetricEncryptAndDecrypt(t, "aes_key", "AES/GCM/PKCS5Padding")
	_testSymmetricEncryptAndDecrypt(t, "aes_key", "AES/GCM/NoPadding")

	_testSymmetricEncryptAndDecrypt(t, "des_key", "DES/ECB/PKCS5Padding")
	_testSymmetricEncryptAndDecrypt(t, "des_key", "DES/CBC/PKCS5Padding")
	_testSymmetricEncryptAndDecrypt(t, "des_key", "DES/CTR/PKCS5Padding")
	_testSymmetricEncryptAndDecrypt(t, "des_key", "DES/CTR/NoPadding")

	_testSymmetricEncryptAndDecrypt(t, "3des_key", "3DES/ECB/PKCS5Padding")
	_testSymmetricEncryptAndDecrypt(t, "3des_key", "3DES/CBC/PKCS5Padding")
	_testSymmetricEncryptAndDecrypt(t, "3des_key", "3DES/CTR/PKCS5Padding")
	_testSymmetricEncryptAndDecrypt(t, "3des_key", "3DES/CTR/NoPadding")
}

func _testSymmetricEncryptAndDecrypt(t *testing.T, keyName string, algo string) {
	plaintext := []byte("By your command!")
	response, err := testVssmService.SymmetricEncrypt(nil, &vssmpb.SymmetricEncryptRequest{
		Input:     plaintext,
		KeyName:   keyName,
		Algorithm: algo,
	})
	if err != nil {
		t.Errorf("Bad encrypt (%s): %v", algo, err)
		return
	}
	ciphertext := response.Output

	decryptResponse, err := testVssmService.SymmetricDecrypt(nil, &vssmpb.SymmetricDecryptRequest{
		Input:     ciphertext,
		KeyName:   keyName,
		Algorithm: algo,
	})
	if err != nil {
		t.Errorf("Bad decrypt (%s): %v", algo, err)
		return
	}
	decryptedText := decryptResponse.Output

	if !bytes.Equal(plaintext, decryptedText) {
		t.Errorf("Incorrect decrypt (%s): %s != %s", algo, plaintext, decryptedText)
		return
	}
}

func TestSymmetricKnownPlaintextDecrypt(t *testing.T) {
	_testSymmetricKnownPlaintextDecrypt(t, "test_aes_key", "AES/ECB/PKCS5Padding", "KF8XCKwExtQ4itcvgi8hjAs/W2vwRMsZx3rpWjmD+N29LxeXjlpPhNPpylips8V1")
	_testSymmetricKnownPlaintextDecrypt(t, "test_aes_key", "AES/CBC/PKCS5Padding", "d+0zERpyGl2r5b7i23GMJFdMybAeqMP8oXuiotqg6LPDLdTiR2Q2r4jhsGdnBmpXKtJ1BBptjmhXlHehSQ35FA==")
	_testSymmetricKnownPlaintextDecrypt(t, "test_aes_key", "AES/CTR/PKCS5Padding", "JmTrKgPcrbnuHQj3CVHXG48MDlF37HNiZ1SMWJpXLI8bcKenkO0Wo0ogiTMGbFFOcb5pBySrWpPTeE1W1wbeSQ==")
	_testSymmetricKnownPlaintextDecrypt(t, "test_aes_key", "AES/CTR/NoPadding", "s/1gKm6M1HMJ8Wa9DTT1ayN5eRYylrpmR1XW9d13cy0niXB20iE4evwxwyfrCCB2Ae+lY68qzMtfLsOY")
	_testSymmetricKnownPlaintextDecrypt(t, "test_aes_key", "AES/GCM/PKCS5Padding", "TesKA8zaoE2MB46KHlu2dd4lH4XUOhwCq1XOcDTwEIzhXwD2Tel+5kVd1DRXQyybExQJbLKt1v94hBmcTy7u7Bjc10pefC/VeJPfdg==")
	_testSymmetricKnownPlaintextDecrypt(t, "test_aes_key", "AES/GCM/NoPadding", "mArzEdkYwt9ErjzZtYhctkSjFvNz94BUtRjFDyx3iFTUtyb7wHh7QaYkmh7odWaFtdI4husyH0uF+7eX5iGbpWVBFEZqlpYZ")

	_testSymmetricKnownPlaintextDecrypt(t, "test_des_key", "DES/ECB/PKCS5Padding", "j2Pfl3YPVQkcqAOVr2alSKg+2U3WKyOvWgNsF0+uHLOQevPEVKHWitdwyZLN+OJW")
	_testSymmetricKnownPlaintextDecrypt(t, "test_des_key", "DES/CBC/PKCS5Padding", "Wv11TI8Vhj9hx+Y99mdu+S6ckAv6c44PHkciYp9MZ/JhU6DLJmThq4NVZvzZaWSRnBeIuayiu0A=")
	_testSymmetricKnownPlaintextDecrypt(t, "test_des_key", "DES/CTR/PKCS5Padding", "43fip3MRIdf6z789isThRkJZpPx0My7PEtfYXTFtN0ZA0x50BgGe2S4TK2D85YKIIbAqW8HqpPw=")
	_testSymmetricKnownPlaintextDecrypt(t, "test_des_key", "DES/CTR/NoPadding", "fvyp06Lg0/O2HFF2fcwEfM6FQ/adezdexttcuWCJq7cz+pBkvuLPj6rUf58BZ3hry2ymGg==")

	_testSymmetricKnownPlaintextDecrypt(t, "test_3des_key", "3DES/ECB/PKCS5Padding", "avEjC0/tY0zSFHv/noiKRpahy9t9atLtyvHYUCYnbg3l54AGVV73uU54ymOw3gHC")
	_testSymmetricKnownPlaintextDecrypt(t, "test_3des_key", "3DES/CBC/PKCS5Padding", "+/sIzrVhjFh7muhk2WhgNaDzRDkt7wEk7Lo6XkHWQ1ofsbUvzhFwnZrYIZVTN1rZ7M2Vk1P1zCY=")
	_testSymmetricKnownPlaintextDecrypt(t, "test_3des_key", "3DES/CTR/PKCS5Padding", "hKvVkzUP7BIXOkDcRes1GhQ2MUUWMrU8zbzOEvtCnoznhI7cpcmvFTRR+2U2TFny5Utm7vsR4IM=")
	_testSymmetricKnownPlaintextDecrypt(t, "test_3des_key", "3DES/CTR/NoPadding", "VRS02KdEgbhOE41wCanbhoolLM5tQbHdjujag+cCenr+GHccCnpXYt7tk3QqhpaVUktXdw==")
}

func _generateSymmetricKnownPlaintextEncrypt(t *testing.T, keyName string, algo string) {
	plaintext := []byte("Then said they unto him, Say now Shibboleth.")
	response, err := testVssmService.SymmetricEncrypt(nil, &vssmpb.SymmetricEncryptRequest{
		Input:     plaintext,
		KeyName:   keyName,
		Algorithm: algo,
	})
	if err != nil {
		t.Errorf("Bad decrypt (%s): %v", algo, err)
		return
	}
	ciphertext := base64.StdEncoding.EncodeToString(response.Output)
	fmt.Printf("%s: %s\n", algo, ciphertext)
}

func _testSymmetricKnownPlaintextDecrypt(t *testing.T, keyName string, algo string, ciphertext string) {
	plaintext := []byte("Then said they unto him, Say now Shibboleth.")
	cipherbytes, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		t.Fatal(err)
	}

	response, err := testVssmService.SymmetricDecrypt(nil, &vssmpb.SymmetricDecryptRequest{
		Input:     cipherbytes,
		KeyName:   keyName,
		Algorithm: algo,
	})
	if err != nil {
		t.Errorf("Bad decrypt (%s): %v", algo, err)
		return
	}

	if !bytes.Equal(plaintext, response.Output) {
		t.Errorf("Incorrect decrypt (%s): %s != %s", algo, plaintext, response.Output)
		return
	}
}

func TestAsymmetricEncryptAndDecrypt(t *testing.T) {
	_testAsymmetricEncryptAndDecrypt(t, "rsa_2048", "RSA")
	_testAsymmetricEncryptAndDecrypt(t, "rsa_2048", "RSA-OAEP/SHA1")
	_testAsymmetricEncryptAndDecrypt(t, "rsa_2048", "RSA-OAEP/SHA256")
	_testAsymmetricEncryptAndDecrypt(t, "rsa_2048", "RSA-OAEP/SHA384")
	_testAsymmetricEncryptAndDecrypt(t, "rsa_2048", "RSA-OAEP/SHA512")
}

func _testAsymmetricEncryptAndDecrypt(t *testing.T, keyName string, algo string) {
	plaintext := []byte("Dear Princess Celestia...")
	response, err := testVssmService.AsymmetricEncrypt(nil, &vssmpb.AsymmetricEncryptRequest{
		Input:     plaintext,
		KeyName:   keyName,
		Algorithm: algo,
	})
	if err != nil {
		t.Errorf("Bad encrypt (%s): %v", algo, err)
		return
	}
	ciphertext := response.Output

	decryptResponse, err := testVssmService.AsymmetricDecrypt(nil, &vssmpb.AsymmetricDecryptRequest{
		Input:     ciphertext,
		KeyName:   keyName,
		Algorithm: algo,
	})
	if err != nil {
		t.Errorf("Bad decrypt (%s): %v", algo, err)
		return
	}
	decryptedText := decryptResponse.Output

	if !bytes.Equal(plaintext, decryptedText) {
		t.Errorf("Incorrect decrypt (%s): %s != %s", algo, plaintext, decryptedText)
		return
	}
}

func TestAsymmetricKnownPlaintextDecrypt(t *testing.T) {
	_testAsymmetricKnownPlaintextDecrypt(t, "test_rsa_2048", "RSA", "VXgRQuS46uQpHDXkhckZPqOZtiGX9vqlG/Y15TiZxgZduAgq9V9Ve/L4Z9lKKlXlLGAatHG6RJo+hKDI/FP7wd/BCcwyZMn7p5AYRiqZxJFhrUq7x9viVeYx9jfAqcZXWR9Y0DkCZDs3Lw4otyCLZADnQ5A+FKoMMiDRJmO/UGa7/omTzzjvaF/YHx96LTb2U13ag6DGMs05Yli18xUYoSzcbDuVc+8BKeURdb6O4d5N2vTHELG7QiZGSrJteSiJIJfY5sdfqSCjAh0n9unwBaHPi3inA0Ec9zAFoE106h+bJsSXSf3roeN+Ojce3OY9BzFeobJK/qCwqBcEEjQtAg==")
	_testAsymmetricKnownPlaintextDecrypt(t, "test_rsa_2048", "RSA-OAEP/SHA1", "47NpqPYxE1VN3q0PgUOl039J3wRifw9SWluOdlPXXVfhVgQpFzMUiTjzDB2k3bn+54Es7SNHxNRBcKT7Kw+xp2J4/5pE34KHFlbA8KHhk8j9FibUvg3csh1JTP46/rqq3kuT9mwZbvpkCl9TDBJgbNr0iFC1mvYqhmYB8diBvJzvX0Na09zUbX/cL+w+LuFd6nw4a4SSs7KzeUMjO+1CT+u3wKHfVehkj7CqaNPfrUPC23dHS8JrDBbcMia2oibXUZS3HBFGRM7Htgx64qNboPaMY41+54KoeFBlwP9EipyCHDIQuFKr9wBMTaV0W54LU2QAE+gZvHqMLgQ3EZ91Hw==")
	_testAsymmetricKnownPlaintextDecrypt(t, "test_rsa_2048", "RSA-OAEP/SHA256", "7zxucOnLBZ6BcrBii+VGXLfPGJIErEiagvxFhVdlzoZFwXh6voIpfXCxoZCANjE3JShDYLWdgXm+D1E4SYytC9zGcyv+mRCcJsiVF5eVnOa3ZZAy/6MZrgWnpGVkjSBB0izpzzK2RNAM7/QCxYoDpvhnM+CQT5qGx/eHOqwbuNAllCU17i1MLupWWHb63aWn5yxxuw0le4XaE+sfL3LZaJzxTKsANM7feiGwSy/8f/2PrpE7I6B4s56fNhvrLiubvR/ULoU8eDFVNqxF07P3xseUjXAYf/68fZpYbaq0yqJPMgejfr3JLQDqMJcU6idvWluIpBaUThsrNo0cOyQgKg==")
	_testAsymmetricKnownPlaintextDecrypt(t, "test_rsa_2048", "RSA-OAEP/SHA384", "I6p8mwY4sPImznVCTW23eaVmGa+a1N3xpJrnQsEHAlFbS2Lz6S25Rb0Y9sDxN6fxlzA8smxAmi0wKql+pjoYog7tReGlqcgdSC5Z4qjxhYnaaHehthTxUDh+5RCwLKO4lfXPK1fH8QbbJuuq6mmqSIY+fqqcbdRLzdH45jzkHJnR/E9GZ5U+mBVk4BmooFwztIEUL23xzwOKG3N5rH/82mbzYYWdhVDLvCe25UDX7mgmfn/YJEnD7oy+OkwnBEGrdxmhUN7ZEF2hsaseUXLVrY3GZCxDk+eTBfYHWGumCghGDadACUkw0Ht7FuWuKxIbIGlyRu9rv140cKlEsGoE3A==")
	_testAsymmetricKnownPlaintextDecrypt(t, "test_rsa_2048", "RSA-OAEP/SHA512", "r/ToxKrm/P0K2MELOu5jGn49PkaT1cAz5IQRw3T+eORUUe+AaD6IkL2mnwHqxLeDo2x3ehQ58JF4VHjQxq9k08A5b78o/2fziDmAF+HyN9uAgXO6Ibmz1BOkAwQu9GzfmI8iEHGvHh4E7o/6mchO2Q6nizoMNydU9cdkuqZYl8LjXZNpQBVRMz9suL9j2WQPGN8YtMo8A+xUFMksUeLnkrXS8daBl/LrAyCuilVKkVOlXe0JbmEX/LsekXpSsZtG9/9tonuVXvSNlVGD2ut/afQZ5rO1ktoknLu4QdjugN6Q8uA7nxjxml9G6nszzbO1YKiYWlRD5/4Cz/2w78XddQ==")
}

func _generateAsymmetricKnownPlaintextEncrypt(t *testing.T, keyName string, algo string) {
	plaintext := []byte("Your faithful student, Twilight Sparkle")
	response, err := testVssmService.AsymmetricEncrypt(nil, &vssmpb.AsymmetricEncryptRequest{
		Input:     plaintext,
		KeyName:   keyName,
		Algorithm: algo,
	})
	if err != nil {
		t.Errorf("Bad decrypt (%s): %v", algo, err)
		return
	}
	ciphertext := base64.StdEncoding.EncodeToString(response.Output)
	fmt.Printf("%s: %s\n", algo, ciphertext)
}

func _testAsymmetricKnownPlaintextDecrypt(t *testing.T, keyName string, algo string, ciphertext string) {
	plaintext := []byte("Your faithful student, Twilight Sparkle")
	cipherbytes, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		t.Fatal(err)
	}

	response, err := testVssmService.AsymmetricDecrypt(nil, &vssmpb.AsymmetricDecryptRequest{
		Input:     cipherbytes,
		KeyName:   keyName,
		Algorithm: algo,
	})
	if err != nil {
		t.Errorf("Bad decrypt (%s): %v", algo, err)
		return
	}

	if !bytes.Equal(plaintext, response.Output) {
		t.Errorf("Incorrect decrypt (%s): %s != %s", algo, plaintext, response.Output)
		return
	}
}

func TestAsymmetricSignAndVerify(t *testing.T) {
	_testAsymmetricSignAndVerify(t, "rsa_2048", crypto.SHA1, "SHA1withRSA")
	_testAsymmetricSignAndVerify(t, "rsa_2048", crypto.SHA256, "SHA256withRSA")
	_testAsymmetricSignAndVerify(t, "rsa_2048", crypto.SHA384, "SHA384withRSA")
	_testAsymmetricSignAndVerify(t, "rsa_2048", crypto.SHA512, "SHA512withRSA")

	_testAsymmetricSignAndVerify(t, "ec_p256", crypto.SHA1, "SHA1withECDSA")
	_testAsymmetricSignAndVerify(t, "ec_p256", crypto.SHA256, "SHA256withECDSA")
}

func _testAsymmetricSignAndVerifyWith(t *testing.T, keyName string, algo string,
	signInput []byte, signHashed []byte, verifyInput []byte, verifyHashed []byte, expected bool) {

	response, err := testVssmService.AsymmetricSign(nil, &vssmpb.AsymmetricSignRequest{
		Input:     signInput,
		Hashed:    signHashed,
		KeyName:   keyName,
		Algorithm: algo,
	})
	if err != nil {
		t.Fatal(err)
	}
	signature := response.Output

	verifyResponse, err := testVssmService.AsymmetricVerify(nil, &vssmpb.AsymmetricVerifyRequest{
		Input:     verifyInput,
		Hashed:    verifyHashed,
		Signature: signature,
		KeyName:   keyName,
		Algorithm: algo,
	})
	if err != nil {
		t.Fatal(err)
	}
	isValid := verifyResponse.Valid

	if isValid != expected {
		t.Errorf("Got invalid verify result (%s)", algo)
	}
}

func _testAsymmetricSignAndVerify(t *testing.T, keyName string, hash crypto.Hash, algo string) {
	plaintext := []byte("Steve can, like, totally read all this stuff.")
	h := hash.New()
	h.Write(plaintext)
	hashed := h.Sum(nil)

	badPlaintext := []byte("Eve can, like, totally read all this stuff, too.")
	h = hash.New()
	h.Write(badPlaintext)
	badHashed := h.Sum(nil)

	_testAsymmetricSignAndVerifyWith(t, keyName, algo,
		plaintext, nil, plaintext, nil, true)
	_testAsymmetricSignAndVerifyWith(t, keyName, algo,
		nil, hashed, plaintext, nil, true)
	_testAsymmetricSignAndVerifyWith(t, keyName, algo,
		plaintext, nil, nil, hashed, true)
	_testAsymmetricSignAndVerifyWith(t, keyName, algo,
		nil, hashed, nil, hashed, true)
	_testAsymmetricSignAndVerifyWith(t, keyName, algo,
		badPlaintext, nil, plaintext, nil, false)
	_testAsymmetricSignAndVerifyWith(t, keyName, algo,
		nil, badHashed, plaintext, nil, false)
	_testAsymmetricSignAndVerifyWith(t, keyName, algo,
		plaintext, nil, badPlaintext, nil, false)
	_testAsymmetricSignAndVerifyWith(t, keyName, algo,
		plaintext, nil, nil, badHashed, false)
}

func TestAsymmetricKnownSignatureVerify(t *testing.T) {
	_testAsymmetricKnownSignatureVerify(t, "test_rsa_2048", crypto.SHA1, "SHA1withRSA", "021frp4h9bZdnngGXIVF5sBoahCtAVcH5cozGVQ9DW6j+Rlkr+5CCj+TZI3NhcCJlrmUYxkRzO9oeez7/17a1EG8MmcGQlpvI5G85bHo0nQl3WqvpIDqOwVmOAv5kTGL5HrVGai8yYFhFdX7UQd9AC0EOWkFe7bOPrUye8ox8sjBPqeyC6GHhp01YLYLEA4Jig/js3egE/w3x2LbDnMMd/sOV1O+kBwC9pg79zQSmGIpnpBXMo11DOyf6rqPVLG417yRP6RRerYfWW/8gYx3qymCHdYdDnvHpM5sgJaVg/36Ob/L9/ALVRHHk2K9yRYPxwapxyoi5IyDdw6TtJVPIQ==")
	_testAsymmetricKnownSignatureVerify(t, "test_rsa_2048", crypto.SHA256, "SHA256withRSA", "ANSSKWYV6kvTyYAChlK/DEwx/810pGa7vKOoH5L8g3xjEMZrDtXqRJiovAO6pw7cob1j6WY8Tp+9XBL3sc6sQ5s9IYln1gED6rpEdznqMzOl4DbOyysqrw4U5nEYMvkAVnaRQNqYgdj2x9MsvZ3AfnhgX6hp9HibasVU5uqBYMyJ2XhEeJGgkoknaxC46PUSXzF/W2rwoRKXHsq1zLznxJFZs5HCerDlKnh4nN5epFuoTXmE3twQuS8TL1amov17vIE6u/2vrK44ucHoTrgcvycS2AmqTjY7ow8PdF90Ny7NuX3Fqv9wEgf4+G5tKsppvVtuqBBr3PiglQ8uGsy3iA==")
	_testAsymmetricKnownSignatureVerify(t, "test_rsa_2048", crypto.SHA384, "SHA384withRSA", "1Ae+P354l4Wfz31G9GreHiigaI5tWjMth0EIMdEHxTyVeEuu3X7c8ScVPY1oHxpu202M7yXAUvu8HN/R4miFkRGMYV6YGRBZ0/MVc80WAC3XCkiabOMefhzin8ln2Pv9nmY1ooxBCMs1yTqOMNGweDISGrtmKsCOJoYT0R74vbtENcTFT/7Xdsx0qC8GASQGUivCe3q0NYXu/E5LrzV3wXl2HdO9TFGRjE20A0FV/rhy01HXPM2Cmk0o/PTARHaoEPLBgcJyDPk90x0lrJbH5NbmaslGuBDuA9AulZ3nCAt3hNF5a759tfH0gTNbtiGY4X8cUGoMCxGbTF+azBFZoA==")
	_testAsymmetricKnownSignatureVerify(t, "test_rsa_2048", crypto.SHA512, "SHA512withRSA", "e2tdJL+oovz4mvSuszyySn6rgX0UNXxik38O/JdvvyBgO5qalNj4SooypsCPxn/cCyIi164tlZQpJL9OfVG5/5RNhPIy7xufBxzgi8tDmftHqfTeJnI7fTfw1/vvzy8fnFJN/K4XmVcjYgCKXsgfkOL+GJCnu2t5d/3JeUsxRm1O+8xRN1xUstKDRIYMEfPsSuB2jH+/qGwBzJTDig0vF+mwjH0VZgZEAm9kG637nHvz9hq4fdApxf1ZF0UKY1U6te6GWjur9N4Zk4Bek8mTVs12x29wb9ZkIvQlzy2ZpnjSoPp8/fPh6+J+ajMmLfmB/zIzQSHaSqZ/wIucE4RW4Q==")

	_testAsymmetricKnownSignatureVerify(t, "test_ec_p256", crypto.SHA1, "SHA1withECDSA", "MEUCIQCcE7MNiN8gFUzOgoB+DOGDUr7pdDq/z+0FiKu2k/wR0gIgUs8VjqkCE8IlEPRESjw3gPPFfs0uxAQMKnCLbMMY96c=")
	_testAsymmetricKnownSignatureVerify(t, "test_ec_p256", crypto.SHA256, "SHA256withECDSA", "MEUCIQCTqYpsTSgGBijmaW92678GyxqX2fzwAXzpWunO1EBmHQIgca08byE+jhbt64mpjsEljH9fqnMZKUI4a3w5S6aEfaM=")
}

func _generateAsymmetricKnownSignature(t *testing.T, keyName string, algo string) {
	plaintext := []byte("If you're reading this, I suggest taking a break and getting some coffee.")

	response, err := testVssmService.AsymmetricSign(nil, &vssmpb.AsymmetricSignRequest{
		Input:     plaintext,
		KeyName:   keyName,
		Algorithm: algo,
	})
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("%s %s\n", algo, base64.StdEncoding.EncodeToString(response.Output))
}

func _testAsymmetricKnownSignatureVerify(t *testing.T, keyName string, hash crypto.Hash, algo string, signature string) {
	plaintext := []byte("If you're reading this, I suggest taking a break and getting some coffee.")
	h := hash.New()
	h.Write(plaintext)
	hashed := h.Sum(nil)

	sig, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		t.Fatal(err)
	}

	verifyResponse, err := testVssmService.AsymmetricVerify(nil, &vssmpb.AsymmetricVerifyRequest{
		Input:     plaintext,
		Signature: sig,
		KeyName:   keyName,
		Algorithm: algo,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !verifyResponse.Valid {
		t.Errorf("Invalid verify response (%s)", algo)
		return
	}

	verifyResponse, err = testVssmService.AsymmetricVerify(nil, &vssmpb.AsymmetricVerifyRequest{
		Hashed:    hashed,
		Signature: sig,
		KeyName:   keyName,
		Algorithm: algo,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !verifyResponse.Valid {
		t.Errorf("Invalid verify response (%s)", algo)
		return
	}
}

func TestHmacCreateAndVerify(t *testing.T) {
	_testHmacCreateAndVerify(t, "mac_key", "SHA1")
	_testHmacCreateAndVerify(t, "mac_key", "SHA256")
	_testHmacCreateAndVerify(t, "mac_key", "SHA384")
	_testHmacCreateAndVerify(t, "mac_key", "SHA512")
}

func _testHmacCreateAndVerifyWith(t *testing.T, keyName string, algo string,
	input []byte, verifyInput []byte, expected bool) {

	response, err := testVssmService.HmacCreate(nil, &vssmpb.HmacCreateRequest{
		Input:     input,
		KeyName:   keyName,
		Algorithm: algo,
	})
	if err != nil {
		t.Fatal(err)
	}
	hmac := response.Output

	verifyResponse, err := testVssmService.HmacVerify(nil, &vssmpb.HmacVerifyRequest{
		Input:     verifyInput,
		Hmac:      hmac,
		KeyName:   keyName,
		Algorithm: algo,
	})
	if err != nil {
		t.Fatal(err)
	}
	isValid := verifyResponse.Valid

	if isValid != expected {
		t.Errorf("Got invalid verify result (%s)", algo)
	}
}

func _testHmacCreateAndVerify(t *testing.T, keyName string, algo string) {
	plaintext := []byte("This is definitely known a spoofed message.")
	badPlaintext := []byte("This is probably a spoofed message, though.")

	_testHmacCreateAndVerifyWith(t, keyName, algo,
		plaintext, plaintext, true)
	_testHmacCreateAndVerifyWith(t, keyName, algo,
		badPlaintext, plaintext, false)
	_testHmacCreateAndVerifyWith(t, keyName, algo,
		plaintext, badPlaintext, false)
}

func TestHmacKnownMacVerify(t *testing.T) {
	_testHmacKnownMacVerify(t, "mac_key", "SHA1", "gkGnskrMtkFyVK02gtFOXqdEWgk=")
	_testHmacKnownMacVerify(t, "mac_key", "SHA256", "oxAQ9eLET2bv75ko+z/2/A+3rp/vcYNYCA+qQ5pyc5w=")
	_testHmacKnownMacVerify(t, "mac_key", "SHA384", "FIxHdC0QxM082yra+jvaF/DomJC8b6SzeZC24QOU6bYgsdFDji+XbDEfiJtjaQ0f")
	_testHmacKnownMacVerify(t, "mac_key", "SHA512", "gT1vpBkfsdZAyrH7q4RtxYF94JbEO5PbdS5oC4wi4c5hZAEl/NlTQ63NKJCaTH+E8V8ZeNO1Ztqm9+I2JyEi3w==")
}

func _generateHmacKnownMac(t *testing.T, keyName string, algo string) {
	plaintext := []byte("This data has been authenticated!")

	response, err := testVssmService.HmacCreate(nil, &vssmpb.HmacCreateRequest{
		Input:     plaintext,
		KeyName:   keyName,
		Algorithm: algo,
	})
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("%s %s\n", algo, base64.StdEncoding.EncodeToString(response.Output))
}

func _testHmacKnownMacVerify(t *testing.T, keyName string, algo string, hmacB64 string) {
	plaintext := []byte("This data has been authenticated!")

	hmac, err := base64.StdEncoding.DecodeString(hmacB64)
	if err != nil {
		t.Fatal(err)
	}

	verifyResponse, err := testVssmService.HmacVerify(nil, &vssmpb.HmacVerifyRequest{
		Input:     plaintext,
		Hmac:      hmac,
		KeyName:   keyName,
		Algorithm: algo,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !verifyResponse.Valid {
		t.Errorf("Invalid verify response (%s)", algo)
		return
	}
}
