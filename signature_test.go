package natrium

import "testing"

func TestSignatureNormal(t *testing.T) {
	priv := EdDSAGenerateKey()
	message := []byte("Hello World")
	signature := priv.Sign(message)
	err := priv.PublicKey().Verify(message, signature)
	if err != nil {
		t.Fail()
	}
}

func TestSignatureFail(t *testing.T) {
	priv := EdDSAGenerateKey()
	message := []byte("Hello World")
	signature := priv.Sign(message)
	// tamper with msg
	message[1] = 10
	err := priv.PublicKey().Verify(message, signature)
	if err == nil {
		t.Fail()
	}
}
