# Architecture

## The CMS subset

CMS (RFC 5652) is a large family — SignedData, EnvelopedData, EncryptedData,
AuthenticatedData, digested and compressed content. `cms` implements exactly one
member, in one mode:

- **SignedData, detached, with signed attributes.**

That is the shape IANA uses for `root-anchors.p7s` and the shape most "sign this
data file" workflows use. Everything else is a deliberate non-goal.

## ASN.1 shapes

The wire structures (RFC 5652) modelled with `encoding/asn1`:

```
ContentInfo         ::= SEQUENCE { contentType OID, content [0] EXPLICIT ANY }
SignedData          ::= SEQUENCE { version, digestAlgorithms SET, encapContentInfo,
                                   certificates [0] IMPLICIT OPTIONAL, crls [1] OPTIONAL,
                                   signerInfos SET OF SignerInfo }
EncapsulatedContentInfo ::= SEQUENCE { eContentType OID, eContent [0] EXPLICIT OPTIONAL }
SignerInfo          ::= SEQUENCE { version, sid, digestAlgorithm, signedAttrs [0] IMPLICIT OPTIONAL,
                                   signatureAlgorithm, signature, unsignedAttrs [1] OPTIONAL }
```

"Detached" means `EncapsulatedContentInfo.eContent` is absent — the signed bytes
are supplied out of band (the `content` argument). `certificates` carries the
signer chain so `Verify` can validate it against the caller's roots.

## Verify flow

0. Refuse a nil root pool (`x509` would read it as the system trust store).
1. Parse `ContentInfo`; require `contentType == id-signedData` and no trailing data.
2. Parse `SignedData` with no trailing data; require the encapsulated content type to be
   `id-data`; decode the SignerInfos one at a time, refusing a ninth; extract the
   certificate set (`x509.ParseCertificate`, skipping context-tagged CertificateChoices
   such as attribute certificates), refusing a 33rd element or an RSA key over 8192 bits.
3. For each `SignerInfo` (the content is hashed once per digest algorithm, and each
   (certificate, time) chain is built once, at most eight per call):
   1. **Check the signed attributes**, which are required (RFC 5652 §5.4): the
      `messageDigest` attribute equals `H(content)` with the signer's digest algorithm,
      the `contentType` attribute is `id-data`, and each of these and `signingTime`
      appears once with one value.
   2. **Resolve the signer certificate** by `IssuerAndSerialNumber` or, for the
      `[0]` form, a non-empty `SubjectKeyIdentifier`. Every matching bundle
      certificate, up to four, is tried in order for steps 3 and 4; a certificate that
      lists key usages but neither `digitalSignature` nor `contentCommitment` is skipped.
   3. **Verify the signature over the signed attributes.** The attributes are
      stored `[0] IMPLICIT` but signed as a universal `SET OF`; the tag byte is
      swapped from `0xA0` to `0x31` (IMPLICIT tagging replaces only the tag, so
      the length and contents are unchanged). RSA and ECDSA verify a digest of that
      DER; Ed25519 verifies the DER itself (PureEdDSA, RFC 8419) and requires the
      signer's digest algorithm to be SHA-512.
   4. **Verify the chain** with the caller's `x509.VerifyOptions`
      (`x509.Certificate.Verify`). `Verify` supplies the roots and clock;
      `VerifyWith` lets the caller control roots, intermediates, key usages, and
      time. Certificates carried in the SignedData are added as intermediates
      when the caller supplies none, so leaf→intermediate→root chains verify.
4. Succeed if any signer verifies; return the verified certificates, one per signing key.
   Revocation is a caller step on the returned certificate (see the trade-off table).

`VerifyAsSigned` is the same flow with each signer's chain clock set to that signer's own
signed `signingTime` (or its certificate's `NotBefore` when absent) instead of the wall
clock, so a write-once resource stays verifiable after a short signing leaf expires — the
signature over immutable bytes is a timeless fact. The time is read in step 3, only after
that signer's signature over its attributes has verified, so no other SignerInfo can choose
it; a zero time is refused. `SigningTime` exposes the first signer's value (trustworthy only
once verification succeeds). `signingTime` is asserted by the signer rather than attested by
a time authority: a holder of the key — an expired or compromised one included — can sign new
content claiming a time inside the certificate's validity window, or omit it to anchor at
`NotBefore`. `VerifyAsSigned` shows the signature verifies with a key that was valid at the
claimed time, not that signing happened then. Pair it with a revocation or known-good-floor
policy.

## Sign flow

`Sign` is the strict inverse: build the signed attributes (`contentType=id-data`,
`messageDigest=H(content)`, optional `signingTime`), encode them as a sorted DER
`SET OF`, sign `H(SET OF attrs)` with the caller's `crypto.Signer` (an Ed25519 key
signs the `SET OF` itself, with SHA-512 as the digest algorithm), and assemble
`SignerInfo → SignedData → ContentInfo` with the signer certificate embedded and
`eContent` omitted (detached).

## Key implementation details / trade-offs

| Detail | Choice | Why |
|---|---|---|
| Signed-attrs re-encoding | Swap `0xA0`→`0x31` on the captured bytes | The exact bytes the signer hashed; avoids re-marshal drift |
| SET OF ordering (Sign) | Sort attribute encodings before concatenating | DER `SET OF` requires sorted elements (interop) |
| Signature algorithm | Verify: chosen from the signer's public-key type, digest from `digestAlgorithm`. Sign: writes `rsaEncryption` + NULL, `ecdsa-with-SHA*`, or `id-Ed25519` | Matches how CMS separates digest and signature algorithms; the written identifiers are what RFC 3370, 5753 and 8419 name and what OpenSSL writes |
| Work limits | 8 SignerInfos, 32 bundle certificates, RSA keys up to 8192 bits, 4 candidate certificates per signer, 8 chain builds per call | A hostile signature cannot buy CPU or memory in proportion to its size; measured worst case about 0.3 s |
| Ed25519 digest | SHA-512 only, in `Sign` and `Verify` | RFC 8419 §3.1 fixes it; accepting another would let a weaker `messageDigest` stand behind an Ed25519 signature |
| Revocation | Not checked; a caller step on the returned signer cert (CRL/OCSP) | Go's `x509.VerifyOptions` has no revocation facility, and revocation policy is caller territory — keeps the package focused (see README §Revocation, `example/revoke`) |
| Content in memory | `[]byte` content and signature | Root-anchors and manifests are small; streaming is unneeded |

## Why standard-library-only is feasible here

The CMS text format is ASN.1 DER, which `encoding/asn1` handles; chain validation
is `crypto/x509`; the signature primitives are `crypto/rsa`, `crypto/ecdsa` and `crypto/ed25519`.
The only thing missing from stdlib was the *glue* — parsing SignedData and
reconstructing the signed-attributes bytes — which is a few hundred lines. That
is exactly the gap this package fills without a dependency.
