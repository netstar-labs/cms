# cms examples

| Example | What it shows |
|---|---|
| [verify](verify/) | Verify a detached CMS signature over a file against a PEM root bundle |
| [revoke](revoke/) | Verify, then enforce revocation on the signer certificate via a CRL |

## verify

```bash
go run ./example/verify -content root-anchors.xml -sig root-anchors.p7s -roots icann-ca.pem
```

Prints the verified signer's subject on success, or the verification error and a
non-zero exit on failure. The signature must be DER (`.p7s`); the roots file is
one or more PEM `CERTIFICATE` blocks trusted out of band.

## revoke

```bash
go run ./example/revoke
```

Builds a CA, a signer leaf, and a CRL in-process, signs content, then runs both
the not-revoked and revoked cases — showing the two-step pattern: authenticate
the CMS signature with `VerifyWith`, then reject the verified signer if it appears
on a CRL whose signature checks out against its issuer.

