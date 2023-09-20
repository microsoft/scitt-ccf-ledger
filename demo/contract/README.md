# Contract Demo

This demo shows participants in the DEPA training framework using a [did:web](https://w3c-ccg.github.io/did-method-web/) identifier hosted on GitHub to sign and submit contracts, receive receipts, and validate them. The specific scenario involves two participants, a training data provider, who provides three datasets, and a TDC who wishes to consume the datasets to train a model. 

## Prerequisites
This demo requires a running contract service, and two GitHub accounts and two GitHub Pages user/organization sites, one for the TDP and one for the TDC. To create a GitHub page site, follow the [GitHub Pages user/organization documentation](https://pages.github.com/). You will be asked to create a new repository with the URL `<username>.github.io`. If you don't have two GitHub accounts or you don't want to use the GitHub Pages site associated with your account, you can create a new user on [GitHub](https://github.com/signup).

## Instructions

The demo folder contains a [sample contract](contract.json). We will start by modifying the contract to reflect the identities of the two participants. 

> **Note:** Replace `<tdp_username>` with the GitHub username of the TDP and `<tdc_username>` being used for this demo, and `<contract_service_url>` with the HTTP endpoint of the contract service setup by the SRO. The script will default to using `http://127.0.0.1:8000` for the contract service. 

```
export TDP_USERNAME=<tdp_username>
export TDC_USERNAME=<tdc_username>
export CONTRACT_URL=<contract_service_url>
./demo/update_contract.sh
```

You can find the new contract in under `tmp/contracts`. 

Next, run the following command to setup and activate your environment.

```
./demo/contract/0-install-cli.sh
source venv/bin/activate
./demo/contract/1-contract-setup.sh
```

Acting as the TDP, run the following commands to create the TDP's DID, and then sign and register a fresh contract:

> **Note:** The `create-did` script creates and uploads the TDPs DID to the TDPs GitHub site. You may be asked to authenticate to GitHub in that process using a password or [personal access token](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens#creating-a-fine-grained-personal-access-token) for the TDP GitHub account. Creating DID is a one-time process; the same DID can be used for signing multiple contracts. 

```
./demo/contract/2-create-did.sh
curl https://${TDP_USERNAME}.github.io/.well-known/did.json
./demo/contract/3-sign-contract.sh
./demo/contract/4-register-contract.sh
./demo/contract/5-view-receipt.sh
```
When a contract is submitted to the contract service, it is assigned a sequence number. For example, if you see the following output, XX is the sequence number assigned to the contract. 

```
Submitted tmp/<tdp_username>/contract.cose as transaction 2.XX
```

Now acting as a TDC, run the following commands to create the TDC's DID, and then retrieve, sign and submit the contract previously registered by the TDP using the TDC's DID:

> **Note:** Replace `<sequence_number>` with the sequence number of the contract the TDC wishes to sign. 

> **Note:** The `create-did` script creates and uploads the TDCs DID to the TDCs GitHub site. You may be asked to authenticate to GitHub in that process using a password or [personal access token](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens#creating-a-fine-grained-personal-access-token) for the TDP GitHub account. 

```
./demo/contract/7-create-did.sh
./demo/contract/8-retrieve-contracts.sh <sequence_number>
curl https://${TDC_USERNAME}.github.io/.well-known/did.json
./demo/contract/9-sign-contract.sh
./demo/contract/10-register-contract.sh
```

If all goes well, the signed contract is registered, and the TDC can proceed the next stage of setting up CCR to train their models. 