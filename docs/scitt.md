# SCITT Standard alignment

# Signed Statement Inputs

scitt-ccf-ledger accepts Signed Statement inputs as specified in Section 4.2 of the [Architecture Draft 11](https://datatracker.ietf.org/doc/draft-ietf-scitt-architecture/11/). See tests for details.

# Registration Policy

scitt-ccf-ledger implements registration policy as specified in Section 4.1.1 of the [Architecture Draft 11](https://datatracker.ietf.org/doc/draft-ietf-scitt-architecture/11/). See configuration for details. 

# Hashed Envelope Format

scitt-ccf-ledger has no specific support for the [Hashed Envelope Format Draft](https://cose-wg.github.io/draft-ietf-cose-hash-envelope/draft-ietf-cose-hash-envelope.html), which is not currently implementable because the Header Parameters it introduces have undefined value.

Alignment will require that scitt-ccf-ledger passes these values through correctly, and exposes them to registration policy, which can be captured by a testcase.

# Transparent Statement Output

scitt-ccf-ledger returns Transparent Statement outputs as specified in Section 4.4 of the [Architecture Draft 11](https://datatracker.ietf.org/doc/draft-ietf-scitt-architecture/11/). See tests for details.

# Receipts

scitt-ccf-ledger returns COSE Receipts, either standalone or embedded in Transparent Statement outputs, as specified in Section 4 of the [COSE Receipt Draft 8](https://datatracker.ietf.org/doc/draft-ietf-cose-merkle-tree-proofs/08/), using proofs that follow the [CCF Tree algorithm profile Draft 3](https://datatracker.ietf.org/doc/draft-birkholz-cose-receipts-ccf-profile/03/).

# API

scitt-ccf-ledger is very close to the [SCITT Reference API Draft 04](https://datatracker.ietf.org/doc/draft-ietf-scitt-scrapi/04/), with the only known difference being the asynchronous registration flow, which still follows [SCITT Reference API Draft 03](https://datatracker.ietf.org/doc/draft-ietf-scitt-scrapi/03/).
