// Copyright 2023 Spacemesh Authors. All rights reserved.

package ed25519

import (
	"crypto/ed25519"
	"testing"
)

func Benchmark_Go_Sign(b *testing.B) {
	_, priv, err := GenerateKey(zeroReader{})
	if err != nil {
		b.Fatal(err)
	}
	message := []byte("Hello, world!")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ed25519.Sign(priv, message)
	}
}

func Benchmark_Go_Verify(b *testing.B) {
	pub, priv, err := GenerateKey(zeroReader{})
	if err != nil {
		b.Fatal(err)
	}
	message := []byte("Hello, world!")
	signature := ed25519.Sign(priv, message)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ed25519.Verify(pub, message, signature)
	}
}

func Benchmark_Spacemesh_Sign(b *testing.B) {
	_, priv, err := GenerateKey(zeroReader{})
	if err != nil {
		b.Fatal(err)
	}

	message := []byte("Hello, world!")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Sign(priv, message)
	}
}

func Benchmark_Spacemesh_Verify(b *testing.B) {
	pub, priv, err := GenerateKey(zeroReader{})
	if err != nil {
		b.Fatal(err)
	}

	message := []byte("Hello, world!")
	signature := Sign(priv, message)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Verify(pub, message, signature)
	}
}

func Benchmark_Spacemesh_KeyExtraction(b *testing.B) {
	_, priv, err := GenerateKey(zeroReader{})
	if err != nil {
		b.Fatal(err)
	}

	message := []byte("Hello, world!")
	sig := Sign(priv, message)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ExtractPublicKey(message, sig)
	}
}
