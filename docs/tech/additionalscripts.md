# Additional Scripts

## General

## Flatten

```sh
mkdir flatten
yarn hardhat flatten contracts/credentials/VerificationRegistry.sol > flatten/VerificationRegistry.sol
```

## Verify with Standard Input JSON

- for blockscout:
  - You will need to take the "input" value from `artifacts/build-info/<SOME_ID>.json` and put it on another file, let's call it "standard_input.json"
  - after having selected the option "Via Standard Input JSON" upload the file "standard_input.json" (created just the step above)
    **Note** in blockcscout the full url path is something like this: `https://<DOMAIN_NAME>/address/<CONTRACT_ADDRESS>/verify-via-standard-json-input/new`

## Check attestation status

```sh
 yarn hardhat run scripts/check.ts --network blerifyAvalancheTestnet
```
