# Executive summary

## What it is

`cms` is a small, standard-library-only Go package that verifies and produces
**detached CMS/PKCS#7 SignedData** signatures (RFC 5652). It fills a specific gap
in the Go standard library: `crypto/x509` verifies certificate chains, but there
is no stdlib primitive to verify a *detached CMS signature over arbitrary
content* — the exact shape used by IANA to sign `root-anchors.xml`, and by many
vendors to sign data files, feeds, and update manifests.

## Why it exists

netstar-labs produces and consumes signed data across the platform, and needs one
audited way to prove a signed blob is authentic. The gap is specifically detached
CMS: many producers (OpenSSL, IANA, common signing tools) emit a detached
`.p7s` over a data file, and there is no stdlib primitive to verify it. Rather
than vendor a heavyweight third-party PKCS#7 library (and take on its CGo/attack
surface) or duplicate a verifier inside every consumer, `cms` is the single
netstar-labs-owned, standard-library-only implementation that any repo imports.

The canonical example is the DNSSEC trust-anchor bootstrap (RFC 5011 / RFC 9718):
IANA distributes the root anchors with a detached CMS signature
(`root-anchors.p7s`) chaining to the ICANN CA, and verifying it was previously
impossible with the standard library alone — the concrete gap this package fills.

## What it enables

- **Signed data across the platform.** Verify — and, via `Sign`, *produce* —
  signed feed/RPZ bundles, `refs` resources, `scribe` archives, `core` bundles
  and patches, and update manifests, so netstar-labs can sign at the source and
  verify at every consumer (the supply-chain-integrity loop).
- **Authenticity + expiration.** Because verification checks the signer chain and
  its validity window, signed artifacts can carry an expiry — the basis for
  expiring data and software. (See the local signing/expiration plan.)
- **DNSSEC trust-anchor bootstrap** (the motivating example): authenticate
  `root-anchors.xml` against `root-anchors.p7s` and the ICANN root, closing the
  RFC 5011 authenticated-bootstrap gap for a DNSSEC-validating consumer.

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
SHA-256/384/512, tamper / wrong-root / expiry negatives), and smoke-tested against
OpenSSL-produced signatures for interoperability. See the
[architecture](architecture.md) for the CMS subset and flow.
