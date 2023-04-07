# GitHub Demo

This demo shows participants in the DEPA training cycle using a [did:web](https://w3c-ccg.github.io/did-method-web/) identifier hosted on GitHub to sign and submit contracts, receive receipts, and validating it.

## Prerequisites
This demo requires a GitHub Pages user/organization site. To create a site, follow the [GitHub Pages user/organization documentation](https://pages.github.com/). 
If you don't have a GitHub account or you don't want to use the GitHub Pages site associated with your account, you can create a new user on [GitHub](https://github.com/signup).

## Instructions
Acting as the contract service operator run:

```
./demo/contract/0-install-cli.sh
source venv/bin/activate
./demo/contract/1-scitt-setup.sh
```

Acting as one of the participant run:

> **Note:** Replace `<username>` with the GitHub username associated with the GitHub Pages site being used for this demo.

```
export GITHUB_USER=<username>  
./demo/contract/2-create-did.sh
curl https://${GITHUB_USER}.github.io/.well-known/did.json
./demo/contract/3-sign-contract.sh
./demo/contract/4-submit-contract.sh
./demo/contract/5-view-receipt.sh
```

Acting as another participant run:
```
export GITHUB_USER1=<username>  
./demo/contract/7-fetch-contract.sh
./demo/contract/8-create-did.sh
curl https://${GITHUB_USER1}.github.io/.well-known/did.json
./demo/contract/9-sign-contract.sh
./demo/contract/10-submit-contract.sh
```
