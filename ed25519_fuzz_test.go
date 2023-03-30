package ed25519

import (
	"math/rand"
	"testing"

	"github.com/spacemeshos/ed25519-recovery/internal/pure25519"
	"github.com/stretchr/testify/require"
)

func Fuzz_ExtractPublicKey(f *testing.F) {
	py, err := pure25519.New()
	if err != nil {
		f.Skip("failed to initialize python bindings:", err)
	}

	f.Add([]byte("Hello, world!"), int64(0))
	f.Fuzz(func(t *testing.T, msg []byte, rndSeed int64) {
		src := rand.New(rand.NewSource(rndSeed))
		seed := make([]byte, 32)

		// generate random seed
		_, err := src.Read(seed)
		require.NoError(t, err, "failed to read random seed")

		// derive key from seed and sign
		key := NewKeyFromSeed(seed)
		sig, err := py.Sign(msg, key.Seed())
		require.NoError(t, err)

		// extract public key from signature
		pub, err := ExtractPublicKey(msg, sig)
		require.NoError(t, err)
		require.EqualValues(t, key.Public(), pub)
	})
}

func Fuzz_Sign(f *testing.F) {
	py, err := pure25519.New()
	if err != nil {
		f.Skip("failed to initialize python bindings")
	}

	f.Add([]byte("Hello, world!"), int64(0))
	f.Fuzz(func(t *testing.T, msg []byte, rndSeed int64) {
		src := rand.New(rand.NewSource(rndSeed))
		seed := make([]byte, 32)

		// generate random seed
		_, err := src.Read(seed)
		require.NoError(t, err, "failed to read random seed")

		// derive key from seed and sign
		key := NewKeyFromSeed(seed)
		sig := Sign(key, msg)

		// extract public key from signature
		pub, err := py.Extract(msg, sig)
		require.NoError(t, err)
		require.EqualValues(t, key.Public(), pub)
	})
}
