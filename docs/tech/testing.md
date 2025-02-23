# Testing Guide

## Testing Commands:

Tests are made against Lacchain Open Pro Testnet because of the Gas Model needed to simulate transactions.

```sh
 yarn hardhat test test/verificationRegistry/VerificationRegistry.test.ts # test on development network
 yarn hardhat test test/verificationRegistry/VerificationRegistryGM.test.ts --network lacchain # run test on a gas model network
```
