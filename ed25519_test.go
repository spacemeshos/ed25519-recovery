// Copyright 2019 Spacemesh Authors
// ed25519 extensions unit tests

package ed25519

import (
	"testing"

	"github.com/stretchr/testify/require"
)

type zeroReader struct{}

func (zeroReader) Read(buf []byte) (int, error) {
	for i := range buf {
		buf[i] = 0
	}
	return len(buf), nil
}

func Test_PublicKeyExtraction(t *testing.T) {
	public, private, err := GenerateKey(zeroReader{})
	require.NoError(t, err)

	// sign the message
	message := []byte("test message")
	sig := Sign(private, message)

	// extract public key from signature and the message
	public1, err := ExtractPublicKey(message, sig)
	require.NoError(t, err)

	// ensure extracted key is the same as public key created by GenerateKey()
	require.EqualValues(t, public, public1, "expected same public key")

	// attempt to extract the public key from the same sig but a wrong message
	wrongMessage := []byte("wrong message")
	public2, err := ExtractPublicKey(wrongMessage, sig)
	require.NoError(t, err)

	// we expect the extracted key to not be the same as the correct signer public key
	require.NotEqual(t, public, public2, "expected different public keys")
}

func Test_SignVerify(t *testing.T) {
	public, private, err := GenerateKey(zeroReader{})
	require.NoError(t, err)

	// sign and verify a message using the public key created by GenerateKey()
	message := []byte("test message")
	sig := Sign(private, message)
	require.True(t, Verify(public, message, sig), "valid signature rejected")

	// Verification of the signature on a wrong message should fail
	wrongMessage := []byte("wrong message")
	require.False(t, Verify(public, wrongMessage, sig), "signature of different message accepted")
}
