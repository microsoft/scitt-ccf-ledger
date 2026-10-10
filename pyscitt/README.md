# pyscitt: Python CLI tools for SCITT CCF Ledger

Tools to interact with a SCITT CCF Ledger and to verify transparent statements.

For more information, please find the `scitt-ccf-ledger` repository at https://github.com/microsoft/scitt-ccf-ledger.

Package sources are available at https://github.com/microsoft/scitt-ccf-ledger/tree/main/pyscitt.

## Installation

```bash
pip install pyscitt
```

## Raw CBOR protected-header values

Use `crypto.RawCbor` when a custom protected-header value has already been
encoded as exactly one CBOR data item and must be included without
re-encoding. Plain `bytes` values are encoded as CBOR byte strings.

```python
from pyscitt import crypto

signed_statement = crypto.sign_statement(
    signer,
    payload,
    content_type="application/json",
    additional_phdr={
        "com.example.signature": crypto.RawCbor(existing_cbor_signature),
    },
)
```

