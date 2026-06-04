# SCITT Standard alignment

## Signed Statement Inputs

scitt-ccf-ledger accepts Signed Statement inputs as specified in Section 4.2 of the [Architecture Draft 11](https://datatracker.ietf.org/doc/draft-ietf-scitt-architecture/11/). See tests for details.

## Registration Policy

scitt-ccf-ledger implements registration policy as specified in Section 4.1.1 of the [Architecture Draft 11](https://datatracker.ietf.org/doc/draft-ietf-scitt-architecture/11/). See configuration for details. 

## Hashed Envelope Format

scitt-ccf-ledger has no specific support for the [Hashed Envelope Format Draft](https://cose-wg.github.io/draft-ietf-cose-hash-envelope/draft-ietf-cose-hash-envelope.html), which is not currently implementable because the Header Parameters it introduces have undefined value.

Alignment will require that scitt-ccf-ledger passes these values through correctly, and exposes them to registration policy, which can be captured by a testcase.

## Transparent Statement Output

scitt-ccf-ledger returns Transparent Statement outputs as specified in Section 4.4 of the [Architecture Draft 11](https://datatracker.ietf.org/doc/draft-ietf-scitt-architecture/11/). See tests for details.

## Receipts

scitt-ccf-ledger returns COSE Receipts, either standalone or embedded in Transparent Statement outputs, as specified in Section 4 of the [COSE Receipt Draft 8](https://datatracker.ietf.org/doc/draft-ietf-cose-merkle-tree-proofs/08/), using proofs that follow the [CCF Tree algorithm profile Draft 3](https://datatracker.ietf.org/doc/draft-birkholz-cose-receipts-ccf-profile/03/).

## API

scitt-ccf-ledger implements the [SCITT Reference API (SCRAPI) Draft 09](https://datatracker.ietf.org/doc/draft-ietf-scitt-scrapi/09/).

### API review clarifications (SCRAPI draft 09)

The SCRAPI draft-09 alignment is enabled when clients use `api-version=2026-03-26`.
Without this api-version (or with unknown versions), legacy behavior is preserved for backward compatibility.

#### Key discovery

- Standard SCRAPI draft-09 endpoints:
  - `GET /.well-known/scitt-keys`
  - `GET /.well-known/scitt-keys/{kid_value}`
- Legacy endpoints (`/jwks` and `/.well-known/transparency-configuration`) are still available for existing clients.

#### Registration and polling

- For `api-version=2026-03-26`:
  - `POST /entries` async flow returns `303 See Other` with `Location: /entries/{txid}`.
  - `GET /entries/{txid}` returns `302 Found` while pending, then `200` with the receipt.
  - `POST /entries?waitForCommit=true` returns `201 Created` with the receipt.
- For legacy clients:
  - `POST /entries` returns `202 Accepted` with `Location: /operations/{txid}`.
  - `GET /operations/{txid}` remains the legacy polling endpoint.

#### Content types

- SCRAPI draft-09 flows use:
  - `application/scitt-receipt+cose` for receipts.
  - `application/scitt-statement+cose` for transparent statements.
- Legacy flows continue to use `application/cose`.

#### Implementation-specific extensions

The following endpoints are kept as implementation-specific extensions and are not part of the SCRAPI draft-09 mandatory surface:

- `/configuration`
- `/version`
- `/jwks`
- `/.well-known/transparency-configuration`
- `/operations/{txid}`
- `/entries/{txid}/statement`
- `/entries/txIds`
