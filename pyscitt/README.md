# pyscitt: Python CLI tools for SCITT CCF Ledger

Tools to sign claims and interact with a SCITT CCF Ledger.

## Validate an RFC 9942 Transparent Statement

`pyscitt` supports RFC 9942 `RFC9162_SHA256` inclusion receipts (`vds=1`)
signed with ES256. Supply a Transparent Statement containing the receipt and
either a service trust store or a trusted PEM service public key:

```shell
scitt validate transparent-statement.cose --service-key log-key.pub
```

For SCITT statements, validation uses the SHA-256 digest of the complete
`COSE_Sign1` statement as the RFC 9162 leaf entry.

For more information, please find the `scitt-ccf-ledger` repository at https://github.com/microsoft/scitt-ccf-ledger.

Package sources are available at https://github.com/microsoft/scitt-ccf-ledger/tree/main/pyscitt.
