# Available clients

## Python CLI

To help with the configuration of an application or to be able to interact with its API you could leverage the available CLI.

The `pyscitt` CLI is written in Python and is available on [public PyPi](https://pypi.org/project/pyscitt/). To install it, you can use the following command:

```sh
pip install pyscitt
```

The CLI is also distributed through the GitHub releases as a `wheel` file. Optionally, it can be used from within the repository using the [`pyscitt.sh`](../pyscitt.sh) script. For example: 

```sh
./pyscitt.sh --help
```

The CLI is extensively used in the following functional tests and demo scripts:

- [Transparency service demo](../demo/transparency-service-poc/README.md)
- [CLI tests](../test/test_cli.py)

See [pyscitt](../pyscitt/README.md) for more details.

## Azure .NET SDK

If the service is running in Azure you can use the following SDK to submit statements, read entries and verify receipts.

```
dotnet add package Azure.Security.CodeTransparency --prerelease
```

- Package information and available versions: https://www.nuget.org/packages/Azure.Security.CodeTransparency 
- Source code with usage samples: https://github.com/Azure/azure-sdk-for-net/tree/main/sdk/confidentialledger/Azure.Security.CodeTransparency 

## CoseSignTool CLI

CoseSignTool can sign payloads in COSE format which is accepted by the service. Please refer to its [GitHub repository](https://github.com/microsoft/CoseSignTool) and section about [SCITT compliance](https://github.com/microsoft/CoseSignTool/blob/main/docs/SCITTCompliance.md).

## Auditing tools

To parse and verify the ledger files use the available ccf utilities, see [documentation](https://microsoft.github.io/CCF/main/audit/python_library.html):

```
pip install ccf
read_ledger.py /path/to/ledger/dir
```

