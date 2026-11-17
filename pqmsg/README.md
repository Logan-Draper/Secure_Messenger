# PqMessenger

Quantum-resistant secure messenger between laptops (applied cryptography course project).
Hybrid X25519 + ML-KEM-768 key exchange, ML-DSA-65 identity signatures, AES-256-GCM with a symmetric ratchet.

> Status: layout skeleton only. Files are placeholders.

## Layout

```
PqMessenger.slnx
Directory.Build.props          shared build settings (target framework, nullable, etc.)
src/
  PqMessenger.Crypto/          primitives wrappers: KEM, signatures, AEAD, KDF, ratchet, fingerprints
  PqMessenger.Protocol/        handshake, transcript, session, wire messages
  PqMessenger.Net/             framing, TCP connection, optional relay
  PqMessenger.Cli/             `pqmsg` app, commands, key/peer storage
tests/
  PqMessenger.Tests/           xUnit tests
docs/                          threat model, protocol spec, architecture, team plan, writeup outline
.github/workflows/ci.yml       build and test on Linux, Windows, macOS
```

Dependencies flow one way: Cli -> Protocol -> Crypto, and Cli -> Net. Net knows nothing about crypto.

## Build and test

```
dotnet build
dotnet test
```
