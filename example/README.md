# cms examples

| Example | What it shows |
|---|---|
| [verify](verify/) | Verify a detached CMS signature over a file against a PEM root bundle |

## verify

```bash
go run ./example/verify -content root-anchors.xml -sig root-anchors.p7s -roots icann-ca.pem
```

Prints the verified signer's subject on success, or the verification error and a
non-zero exit on failure. The signature must be DER (`.p7s`); the roots file is
one or more PEM `CERTIFICATE` blocks trusted out of band.
