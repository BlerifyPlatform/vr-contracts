# Changelog

### 0.1.1

- Feat: Add nonce support for issuance, revoke and onHold signed method
- Feat: Add incremental nonce for adding did registry operations
- Feat: Add incremental nonce for adding delegate types by signed way
- Feat: update by delegate
- Feat: Update by delegate signed
- Feat: Update by custom delegate signed
- Refactor: Update addDidRegistry method to changeDidRegistry

### 0.1.0

- Fix: Emit event when an entity removes its custom didRegistry
- Feat: Add methods to set onHold by default delegate and default delegate with custom type using meta transactions with EIP-712
- Feat: Add methods to add custom DIDRegistry and custom delegate types using meta transactions with EIP-712

### 0.0.9

- Fix: Use contract versions as part of EIP712 signatures
- Refactor: Update version type from 'uint16' to 'string'

## 0.0.2

- Set Contract License to Apache License, Version 2.0
- Creates Generic version of Verification Registry Smart contracts (Valid for any generic Ethereum Based Network)
- Improves documentation

#### Bug Fixes

- Update BaseRelayRecipient to correctly resolve msg sender.

## 0.0.1

- first version of verification registry contracts
  - Gas Model only

### Additions and Improvements

#### Bug Fixes
