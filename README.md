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

The benchmarks can be executed with `go test -bench .`.

```bash
Benchmark_Go_Sign-6                      52352     22548 ns/op       0 B/op       0 allocs/op
Benchmark_Go_Verify-6                    25263     47206 ns/op       0 B/op       0 allocs/op
Benchmark_Spacemesh_Sign-6               52512     22942 ns/op       0 B/op       0 allocs/op
Benchmark_Spacemesh_Verify-6             25344     47545 ns/op       0 B/op       0 allocs/op
Benchmark_Spacemesh_KeyExtraction-6      16887     69857 ns/op       0 B/op       0 allocs/op
```

## Testing

Some of the tests require `python3` and the `pip` package `pure25519` to be installed. These
tests fuzz the implemented functions and compare the results to the python reference
implementation in `internal/pure25519`.

To run the tests, execute `go test ./... -v`. There are also fuzzing tests that can be run with

```bash
go test -fuzz=Fuzz_ExtractPublicKey -fuzztime=20s
go test -fuzz=Fuzz_Sign -fuzztime=20s
go test -fuzz=Fuzz_Derive -fuzztime=20s
```
