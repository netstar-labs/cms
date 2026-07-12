# Executive summary

## What it is

`cms` is a small, standard-library-only Go package that verifies and produces
**detached CMS/PKCS#7 SignedData** signatures (RFC 5652). It fills a specific gap
in the Go standard library: `crypto/x509` verifies certificate chains, but there
is no stdlib primitive to verify a *detached CMS signature over arbitrary
content* — the exact shape used by IANA to sign `root-anchors.xml`, and by many
vendors to sign data files, feeds, and update manifests.

## Why it exists

The `aegis` resolver's RFC 5011 / RFC 9718 trust-anchor bootstrap is blocked
without this primitive: IANA distributes the DNSSEC root anchors with a detached
CMS signature (`root-anchors.p7s`) chaining to the ICANN CA, and there is no
stdlib way to verify it. Rather than vendor a heavyweight third-party PKCS#7
library (and take on its CGo/attack surface) or duplicate a verifier inside every
consumer, `cms` is the single netstar-labs-owned, audited implementation that
`aegis` and its siblings import.

## What it enables

- **DNSSEC trust-anchor bootstrap** (`aegis`): authenticate `root-anchors.xml`
  against `root-anchors.p7s` and the ICANN root, closing the last gap in RFC 5011
  automated anchor management.
- **Signed data across the platform**: verify signed feed/RPZ bundles, signed
  `refs` resources, and update manifests — and, via `Sign`, *produce* them, so
  netstar-labs can close the supply-chain-integrity loop end to end (sign at the
  source, verify at every consumer).

## Design commitments

- **Standard library only.** ASN.1 via `encoding/asn1`, chains via `crypto/x509`,
  signatures via `crypto/rsa` and `crypto/ecdsa`. No CGo, no third-party crypto.
- **Small and auditable.** A single file implementing exactly one CMS shape
  (detached SignedData with signed attributes). Encryption, enveloped data, and
  timestamping are explicit non-goals.
- **Verify and sign symmetric.** `Sign` is the strict inverse of `Verify`, so the
  round-trip is testable without external fixtures, and the platform can both
  emit and consume signed artifacts.

## Status

Verification and signing are implemented and tested end to end (RSA and ECDSA,
SHA-256/384/512, tamper / wrong-root / expiry negatives). The intended consumer
integration is `aegis`'s root-anchor loader. See the
[architecture](architecture.md) for the CMS subset and flow.
