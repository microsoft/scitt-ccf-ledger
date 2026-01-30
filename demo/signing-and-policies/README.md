# Preparing signatures for the service

Signature envelopes (payloads) must be COSE_Sign1 structures as defined in [RFC 8152](https://datatracker.ietf.org/doc/html/rfc8152) but with the specific claims as documented in the [inputs explanation](../../docs/inputs.md).

## Available tools

- [pyscitt Python CLI](../../pyscitt/) can be used to create signature envelopes with the `did:x509` issuer format. There is an example use in the [claim generator demo script](../transparency-service-poc/2-claim-generator.sh)
- [CoseSignTool](https://github.com/microsoft/CoseSignTool) is a cross-compiled CLI tool that can create `did:x509` signature envelopes that will work with the Transparency Service.

## Example using CoseSignTool

### Install CoseSignTool

```bash
curl -LO https://github.com/microsoft/CoseSignTool/releases/latest/download/CoseSignTool-Linux-release.zip
unzip CoseSignTool-Linux-release.zip
mv release ~/.local/bin/cosesigntool
export PATH="$PATH":~/.local/bin/cosesigntool
# Check if invocation works
CoseSignTool
```

### Create a signature envelope

#### Using self signed certificate

Generate certificate chain and create PFX file:

```bash
# generate a self-signed certificate chain
mkdir -p demo-poc/x509_roots
CACERT_OUTPUT_DIR="demo-poc/x509_roots" ./demo/transparency-service-poc/0-cacerts-generator.sh
# create PFX file used by CoseSignTool
cd demo-poc/x509_roots
cat chain-cert-1.pem chain-cert-2.pem > chain.pem
openssl pkcs12 -export -out cacert.pfx -inkey cacert_privk.pem -in cacert.pem -certfile chain.pem
cd ../..
```

Sign a payload file (e.g. `foobar.json`) using the generated PFX file:


```bash
echo '{"example":"data"}' > foobar.json
CoseSignTool sign -payload foobar.json -EmbedPayload true -ContentType "application/json" -PfxCertificate demo-poc/x509_roots/cacert.pfx -SignatureFile foobar.cose
```

Notes:
- The `-EmbedPayload true` flag is required to create a COSE_Sign1 structure with embedded payload.
- The `-ContentType "application/json"` flag sets the content type header to make sure that downstream users understand the type of the payload.
- The output file `foobar.cose` must end in `.cose`.
- There must be more than one certificate in the chain for the Transparency Service to accept the signature.

### Update registration policy

To accept signatures created with the above self-signed certificate, the registration policy must be updated to trust the issuer.

To get the issuer (`did:x509`) value you need a something that can decode COSE structures. `pyscitt` can be used for this. The output will include the parsed `iss` claim, which is the `did:x509` value to add to the registration policy.

```bash
./pyscitt.sh pretty-receipt foobar.cose | grep iss
"iss": "did:x509:0:sha256:0ptTDCtw9jrzQAWzJJ5FTWV3B0DMkRgvqQwEDXw53Z4::subject:CN:893d9743-46ac-48e5-891a-8d13054adb58",
```

Use this value in the registration policy script when configuring the Transparency Service:

```json
{
    "authentication": {
        "allowUnauthenticated": true
    },
    "policy": {
        "policyScript": "export function apply(phdr) { if (!phdr.cwt.iss) {return 'Issuer not set'} else if (phdr.cwt.iss !== 'did:x509:0:sha256:0ptTDCtw9jrzQAWzJJ5FTWV3B0DMkRgvqQwEDXw53Z4::subject:CN:893d9743-46ac-48e5-891a-8d13054adb58') { return 'Invalid issuer'; } return true; }"
    }
}
```
