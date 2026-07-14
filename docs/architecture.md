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

1. Parse `ContentInfo`; require `contentType == id-signedData`.
2. Parse `SignedData`; extract the certificate set (`x509.ParseCertificate`).
3. For each `SignerInfo`:
   1. **Resolve the signer certificate** by `IssuerAndSerialNumber` or, for the
      `[0]` form, `SubjectKeyIdentifier`.
   2. **Check the signed attributes** (RFC 5652 §5.4): the `messageDigest`
      attribute equals `H(content)` with the signer's digest algorithm, and the
      `contentType` attribute value equals the encapsulated content type.
   3. **Verify the signature over the signed attributes.** The attributes are
      stored `[0] IMPLICIT` but signed as a universal `SET OF`; the tag byte is
      swapped from `0xA0` to `0x31` (IMPLICIT tagging replaces only the tag, so
      the length and contents are unchanged) and that DER is hashed and verified.
   4. **Verify the chain** with the caller's `x509.VerifyOptions`
      (`x509.Certificate.Verify`). `Verify` supplies the roots and clock;
      `VerifyWith` lets the caller control roots, intermediates, key usages, and
      time. Certificates carried in the SignedData are added as intermediates
      when the caller supplies none, so leaf→intermediate→root chains verify.
4. Succeed if any signer verifies; return the verified certificates. Revocation
   is a caller step on the returned certificate (see the trade-off table).

`VerifyAsSigned` is the same flow with the chain clock set to the signed
`signingTime` (or the signer's `NotBefore` when absent) instead of the wall clock,
so a write-once resource stays verifiable after a short signing leaf expires — the
signature over immutable bytes is a timeless fact. It parses the first signer's
signed attributes up front to read that time; `SigningTime` exposes the same value
(trustworthy only once verification succeeds). Because `signingTime` is a signed
attribute, a forged or backdated value cannot pass — the signature over the
attributes fails, or the certificate genuinely was valid at the claimed instant.

## Sign flow

`Sign` is the strict inverse: build the signed attributes (`contentType=id-data`,
`messageDigest=H(content)`, optional `signingTime`), encode them as a sorted DER
`SET OF`, sign `H(SET OF attrs)` with the caller's `crypto.Signer`, and assemble
`SignerInfo → SignedData → ContentInfo` with the signer certificate embedded and
`eContent` omitted (detached).

## Key implementation details / trade-offs

| Detail | Choice | Why |
|---|---|---|
| Signed-attrs re-encoding | Swap `0xA0`→`0x31` on the captured bytes | The exact bytes the signer hashed; avoids re-marshal drift |
| SET OF ordering (Sign) | Sort attribute encodings before concatenating | DER `SET OF` requires sorted elements (interop) |
| Signature algorithm | Chosen from the signer's public-key type; digest from `digestAlgorithm` | Matches how CMS separates digest and signature algorithms |
| Revocation | Not checked; a caller step on the returned signer cert (CRL/OCSP) | Go's `x509.VerifyOptions` has no revocation facility, and revocation policy is caller territory — keeps the package focused (see README §Revocation, `example/revoke`) |
| Content in memory | `[]byte` content and signature | Root-anchors and manifests are small; streaming is unneeded |

## Why standard-library-only is feasible here

The CMS text format is ASN.1 DER, which `encoding/asn1` handles; chain validation
is `crypto/x509`; the signature primitives are `crypto/rsa` and `crypto/ecdsa`.
The only thing missing from stdlib was the *glue* — parsing SignedData and
reconstructing the signed-attributes bytes — which is a few hundred lines. That
is exactly the gap this package fills without a dependency.
