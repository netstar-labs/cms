# Meet cms — the seal that rides beside the file, proves who signed it, and decides nothing else

A seal is a promise you can check without trusting the messenger. Press a signet
into wax and anyone downstream can tell two things at a glance: who closed the
letter, and whether it was opened on the way. **CMS** — Cryptographic Message
Syntax (RFC 5652) — is the modern seal, and this package works it in its
*detached* form: the seal does not melt across the document, it rides beside it.
The `root-anchors.xml` file is untouched, plain, readable; a few hundred bytes of
`root-anchors.p7s` travel alongside as the wax. Change one byte of the file and
the seal no longer matches. That is the whole idea, and `cms` is the tool that
presses the seal and the tool that reads it.

Concretely, `cms` is a single standard-library-only Go file that implements
exactly one member of the large CMS family — **SignedData, detached, with signed
attributes** — and nothing else. `Verify(content, sig, roots, now)` parses the
DER `ContentInfo` → `SignedData`, resolves each `SignerInfo`'s certificate (by
issuer-and-serial or subject-key-identifier), confirms the `messageDigest` signed
attribute equals `H(content)` and the `contentType` attribute matches the
encapsulated type (RFC 5652 §5.4), verifies the signature over the DER `SET OF`
attributes, and validates the signer's chain to the roots you supplied — returning
the certificates that passed. `Sign` is the strict inverse: it builds the same
signed attributes, sorts them into a DER `SET OF`, signs the digest with any
`crypto.Signer`, and emits the detached `.p7s`. RSA (PKCS#1 v1.5) and ECDSA;
SHA-256/384/512; issuer-and-serial or subject-key-identifier signers. No CGo, no
third-party crypto — `encoding/asn1`, `crypto/x509`, `crypto/rsa`, `crypto/ecdsa`.

The capability that earns its place: the Go standard library will validate a
certificate chain and check a raw signature, but it ships no primitive that
verifies a *detached CMS signature over content you hold separately* — the exact
shape IANA uses to sign the DNSSEC root anchors, and the shape most "sign this
data file" tools emit. The missing piece was never the cryptography; it was the
glue that parses `SignedData` and reconstructs the precise bytes the signer
hashed. `cms` is those few hundred lines, and it is deliberately those few hundred
and no more — small enough that one person can read all of it before trusting it.

What stays in your hands is the trust itself. `cms` moves a trust root; it does
not manufacture one. You supply the `*x509.CertPool` — and where that pool comes
from (embedded in the binary, installed by a signed channel, or the OS store) is
the real security decision, not an implementation detail. You supply the clock
that decides whether a certificate is still inside its validity window. And you
own revocation: `x509.VerifyOptions` has no CRL or OCSP facility, so if a signer
can be revoked, that check is a step *you* run on the certificate `cms` hands
back. The package verifies authenticity and integrity honestly and refuses to
pretend it decides anything else.

---

Press the seal or check it back — `cms` proves who signed and that nothing
changed. Whose seal to trust, and until when, is yours to decide.

## Read next

- [Executive summary](executive-summary.md) — what it is and why, for leadership
- [Architecture](architecture.md) — the CMS subset, verify/sign flow, trade-offs
- [User guide](userguide.md) — API, wire/file formats, day-2 operations
- [Examples](../example/README.md) — verify a signature, then enforce revocation
