# GitHub Demo

This demo shows participants in the DEPA training cycle using a [did:web](https://w3c-ccg.github.io/did-method-web/) identifier hosted on GitHub to sign and submit contracts, receive receipts, and validating it.

## Prerequisites
This demo requires a GitHub Pages user/organization site. To create a site, follow the [GitHub Pages user/organization documentation](https://pages.github.com/). 
If you don't have a GitHub account or you don't want to use the GitHub Pages site associated with your account, you can create a new user on [GitHub](https://github.com/signup).

## Instructions
Acting as the contract service operator run:

```
./demo/github/0-install-cli.sh
source venv/bin/activate
./demo/github/1-scitt-setup.sh
```

Acting as the contract signer run:

> **Note:** Replace `<username>` with the GitHub username associated with the GitHub Pages site being used for this demo.

```
export GITHUB_USER=<username>  
./demo/github/2-create-did.sh
curl https://${GITHUB_USER}.github.io/.well-known/did.json
./demo/github/3-sign-contract.sh
./demo/github/4-submit-contract.sh
./demo/github/5-view-receipt.sh
```

Acting as another contract signer run:

Acting as the contract consumer run:

```
jq . tmp/trust_store/scitt.json
./demo/github/6-validate.sh
```