# ed25519-recovery

Package ed25519-recovery implements a modified Ed25519 signature algorithm that allows for public key recovery.

It is based on the [Ed25519](https://ed25519.cr.yp.to/) signature scheme implemented by the
[Go 1.20.1 standard library](https://github.com/golang/go/tree/go1.20.1/src/crypto/internal/edwards25519).

ed25519-recovery and achieves public key recovery by removal of the public key from the pre-image of the SHA512 digest
in the calculation of `S`.

## Motivation

Key recovery allows to save on data that needs to be transferred with signed messages. Note: there's a computational
cost for extracting the public key, so one should consider the trade-off between computations and data size.

## Usage

```go
import ed25519 "github.com/spacemeshos/ed25519-recovery"

func example() {
    // Generate a key pair.
    privateKey, publicKey, err := ed25519.GenerateKey(rand.Reader)
    if err != nil {
        panic(err)
    }

    // Sign a message.
    message := []byte("Hello, world!")
    signature := ed25519.Sign(privateKey, message)

    // Extract the public key from the signature...
    extractedPublicKey := ed25519.ExtractPublicKey(message, signature)

    // ... or verify the signature using the public key.
    if !ed25519.Verify(publicKey, message, signature) {
        panic("invalid signature")
    }
}
```

## Benchmarks

TODO
