// Copyright 2019 Spacemesh Authors
// ed25519 extensions unit tests

package ed25519

import (
	"encoding/hex"
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

func Test_Derive(t *testing.T) {
	const expectedEncodedKey = "b6e1caa7ed8fb8b517dbbd5a49f7c9e76f33f0dd74100396207b640479d6fade2b0f080a354fd3c981630efe75bcbc5f4134895b749364f25badeae5a687950c"
	const s = "8d03a58456bb1b45f696032444b09d476fa5406f998ed0a50e694ee8a40cfb09"
	seed, err := hex.DecodeString(s)
	require.NoError(t, err)

	privateKey1 := NewDerivedKeyFromSeed(seed, 5, []byte("Spacemesh rocks"))
	require.Equal(t, expectedEncodedKey, hex.EncodeToString(privateKey1), "Unexpected key")
}
