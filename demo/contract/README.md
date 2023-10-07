# Contract Service Demo

This demo shows participants in the DEPA training framework using a [did:web](https://w3c-ccg.github.io/did-method-web/) identifier hosted on GitHub to sign and submit contracts, receive receipts, and validate them. The specific scenario involves two participants, a training data provider (TDP), who provides three datasets, and a training data consumer (TDC) who wishes to consume the datasets to train a model. 

## Prerequisites

This demo requires a running contract service, and two GitHub accounts and two GitHub Pages user/organization sites, one for the TDP and one for the TDC. To create a GitHub page site, follow the [GitHub Pages user/organization documentation](https://pages.github.com/). You will be asked to create a new repository with the URL `<username>.github.io`. If you don't have two GitHub accounts or you don't want to use the GitHub Pages site associated with your account, you can create a new user on [GitHub](https://github.com/signup).

If you plan to use the contract with a CCR, you will need the location of the key vault that contains the TDP's encryption keys. 

## Contract Creation

The demo folder contains a [sample contract](contract.json). Modify the contract as per your requirements, including
- DIDs of the participants
- names of the datasets
- key identifiers and location of the data encryption keys
- other attributes such as privacy budget

Place the resulting contract in `tmp/contracts`. 

For simplicity, we provide a sample utility which modifies the DIDs of the TDP and TDP and the location of key vault containing the encryption keys. 

> **Note:** Replace `<tdp_username>` with the GitHub username of the TDP, `<tdp_keyvault_url>` is the URL of the Azure Key Vault contains (or will contain) the TDP's encryption keys, `<tdc_username>` being used for this demo, `<contract_service_url>` with the HTTP endpoint of the contract service setup by the SRO. The script will default to using `http://127.0.0.1:8000` for the contract service. 

```bash
export TDP_USERNAME=<tdp_username>
export TDP_KEYVAULT=<tdp_keyvault_url>
export TDC_USERNAME=<tdc_username>
export CONTRACT_URL=<contract_service_url>
./demo/contract/update_contract.sh
```

This script will place the new contract in under `tmp/contracts`. 

## Setup environment

Next, run the following command to setup and activate your environment.

```bash
./demo/contract/0-install-cli.sh
source venv/bin/activate
./demo/contract/1-contract-setup.sh
```

## Sign and register contract as TDP

Acting as the TDP, run the following commands to create the TDP's DID:

> **Note:** The `create-did` script creates and uploads the TDPs DID to the TDPs GitHub site. You will be asked to authenticate to GitHub using [personal access token](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens#creating-a-fine-grained-personal-access-token) for the TDP GitHub account. Please create a PAT that has permissions to read and write to the TDP's GitHub pages repository. Creating DID is a one-time process; the same DID can be used for signing multiple contracts. 

```
./demo/contract/2-create-did.sh
curl https://${TDP_USERNAME}.github.io/.well-known/did.json
```

Next, sign and register a contract, and then view and validate the receipt returned by the contract service.

```bash
./demo/contract/3-sign-contract.sh
./demo/contract/4-register-contract.sh
./demo/contract/5-view-receipt.sh
./demo/contract/6-validate.sh
```

When a contract is submitted to the contract service, it is assigned a sequence number. For example, if you see the following output, XX is the sequence number assigned to the contract. 

```
Submitted tmp/<tdp_username>/contract.cose as transaction 2.XX
```

## Sign and register contract as TDC

Now acting as a TDC, run the following commands to create the TDC's DID:

> **Note:** The `create-did` script creates and uploads the TDCs DID to the TDCs GitHub site. You may be asked to authenticate to GitHub in that process using a password or [personal access token](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens#creating-a-fine-grained-personal-access-token) for the TDP GitHub account. 

```bash
./demo/contract/7-create-did.sh
curl https://${TDC_USERNAME}.github.io/.well-known/did.json
```

Next, retrieve, sign and submit the contract previously registered by the TDP using the TDC's DID

> **Note:** Replace `<sequence_number>` with the sequence number of the contract the TDC wishes to sign. 

```bash
./demo/contract/8-retrieve-contract.sh <sequence_number>
./demo/contract/9-sign-contract.sh <sequence_number>
./demo/contract/10-register-contract.sh
```

If all goes well, the contract signed by both the TDP and TDC is registered. 
