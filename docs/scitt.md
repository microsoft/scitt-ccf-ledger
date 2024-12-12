# SCITT Standard alignment

# Signed Statement Inputs

scitt-ccf-ledger accepts Signed Statement inputs as specified in Section 4.2 of the [Architecture Draft](https://datatracker.ietf.org/doc/draft-ietf-scitt-architecture/). See tests for details.

# Registration Policy

scitt-ccf-ledger implements registration policy as specified in Section 4.1.1 of the [Architecture Draft](https://datatracker.ietf.org/doc/draft-ietf-scitt-architecture/). See configuration for details. 

# Hashed Envelope Format

scitt-ccf-ledger has no specific support for the [Hashed Envelope Format Draft](https://cose-wg.github.io/draft-ietf-cose-hash-envelope/draft-ietf-cose-hash-envelope.html), which is not currently implementable because the Header Parameters it introduces have undefined value.

Alignment will require that scitt-ccf-ledger passes these values through correctly, and exposes them to registration policy, which can be captured by a testcase.

# Transparent Statement Output

scitt-ccf-ledger returns Transparent Statement outputs as specified in Section 4.4 of the [Architecture Draft](https://datatracker.ietf.org/doc/draft-ietf-scitt-architecture/). See tests for details.

# Receipts

scitt-ccf-ledger returns COSE Receipts, either standalone or embedded in Transparent Statement outputs, as specified in Section 4 of the [COSE Receipt Draft](https://datatracker.ietf.org/doc/draft-ietf-cose-merkle-tree-proofs/), using proofs that follow the [CCF Tree algorithm profile Draft](https://datatracker.ietf.org/doc/draft-birkholz-cose-receipts-ccf-profile/).

# API

scitt-ccf-ledger does not currently implement the [SCITT Reference API](https://github.com/ietf-wg-scitt/draft-ietf-scitt-scrapi/blob/main/draft-ietf-scitt-scrapi.md). The following changes are necessary to align:

# Transparency Configuration

See Section 2.1.1

Request

```
GET /.well-known/transparency-configuration HTTP/1.1
Host: transparency.example
Accept: application/cbor
```

Response

```
HTTP/1.1 200 Ok
Content-Type: application/cbor

Payload (in CBOR diagnostic notation)

{
    "issuer": "https://transparency.example",
    "jwks_uri": "https://transparency.example/jwks",
}
```

Note that this differs from the non-normative example list in the spec, in keeping with the statement that elements of the configuration are implementation-specific.

# Register Signed Statement

See Section 2.1.2

Request

```
POST /entries HTTP/1.1
Host: transparency.example
Accept: application/cose
Content-Type: application/cose
Payload (in CBOR diagnostic notation)

18([                            / COSE Sign1         /
  h'a1013822',                  / Protected Header   /
  {},                           / Unprotected Header /
  null,                         / Detached Payload   /
  h'269cd68f4211dffc...0dcb29c' / Signature          /
])
```

Accepted Response

```
HTTP/1.1 202 Accepted

Location: TBD

Content-Type: application/cbor

{

  "identifier": TBD,

}
```

Final success Response

```
HTTP/1.1 201 Ok

Location: TBD

Content-Type: application/cose

Payload (in CBOR diagnostic notation)

18([                            / COSE Sign1         /
  h'a1013822',                  / Protected Header   /
  {},                           / Unprotected Header /
  null,                         / Detached Payload   /
  h'269cd68f4211dffc...0dcb29c' / Signature          /
])
```

Failure example

```
HTTP/1.1 400 Bad Request
application/concise-problem-details+cbor

{
  / title /         -1: "Bad Signature Algorithm",
  / detail /        -2: "Signed Statement contained an algorithm that is not supported",
  / instance /      -3: "urn:ietf:params:scitt:error:badSignatureAlgorithm",
  / response-code / -4: 400,
}
```