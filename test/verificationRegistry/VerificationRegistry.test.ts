import { anyValue } from "@nomicfoundation/hardhat-chai-matchers/withArgs";
import { expect, should } from "chai";
import { ethers, lacchain, network } from "hardhat";
import { keccak256, toUtf8Bytes, formatBytes32String } from "ethers/lib/utils";
import {
  DIDRegistryGM,
  verificationRegistry,
  VerificationRegistry,
  VerificationRegistry__factory,
  VerificationRegistryGM,
  VerificationRegistryGM__factory,
} from "../../typechain-types";
import { BigNumber, Wallet } from "ethers";
import { defaultAbiCoder } from "ethers/lib/utils";
import { arrayify } from "@ethersproject/bytes";
import { DIDRegistry } from "../../typechain-types/utils/identity/didRegistry";
import { DIDRegistry__factory } from "../../typechain-types/factories/utils/identity/didRegistry";
import { DIDRegistryGM__factory } from "../../typechain-types/factories/utils/identity/didRegistryGasModel/DIDRegistry.sol";
import { SignerWithAddress } from "@nomiclabs/hardhat-ethers/signers";
import { GasModelSignerModified } from "../../GasModelModified";
import { randomUUID } from "crypto";
import { identity } from "../../typechain-types/external";

const artifactName = "VerificationRegistryGM";
let deployer: SignerWithAddress | GasModelSignerModified;
let entity1: SignerWithAddress | GasModelSignerModified;
let entity2: SignerWithAddress | GasModelSignerModified;
let entity3: SignerWithAddress | GasModelSignerModified;

let verificationRegistryAddress: string;
let defaultDidRegistryInstance: DIDRegistryGM;
const genericMessage = "some message";
const didRegistryArtifactName = "DIDRegistryGM";
const delegateTypeWithoutPadding = "veriKey";
const defaultDelegateType = formatBytes32String(delegateTypeWithoutPadding); // bytes32 right padded
const EIP712ContractName = "VerificationRegistry";
const unexpectedErrorMessage = "Unexpected failed";
const contractVersion = "010";
describe(artifactName, function () {
  async function deployDidRegistry() {
    let Artifact: DIDRegistry__factory | DIDRegistryGM__factory;
    let didRegistry: DIDRegistry | DIDRegistryGM;
    let owner, account1, account2: SignerWithAddress | GasModelSignerModified;
    const keyRotationTime = 3600;
    if (network.name !== "lacchain") {
      [owner, account1, account2] = await ethers.getSigners();
      Artifact = await ethers.getContractFactory("DIDRegistry", owner);
      didRegistry = await Artifact.deploy(keyRotationTime);
    } else {
      [owner, account1, account2] = lacchain.getSigners();
      Artifact = await ethers.getContractFactory("DIDRegistryGM", owner);
      const instance = await lacchain.deployContract(
        Artifact,
        keyRotationTime,
        lacchain.baseRelayAddress
      );
      didRegistry = Artifact.attach(instance.address);
    }

    return {
      didRegistry,
      owner,
      account1,
      account2,
      Artifact,
    };
  }

  async function deployVerificationRegistry(
    _defaultDelegateType = defaultDelegateType
  ) {
    defaultDidRegistryInstance = (await deployDidRegistry()).didRegistry;

    let Artifact:
      | VerificationRegistry__factory
      | VerificationRegistryGM__factory;
    let verificationRegistry: VerificationRegistry | VerificationRegistryGM;
    let owner, account1, account2: SignerWithAddress | GasModelSignerModified;
    const keyRotationTime = 3600;
    if (network.name !== "lacchain") {
      [owner, account1, account2] = await ethers.getSigners();
      Artifact = await ethers.getContractFactory("VerificationRegistry", owner);
      verificationRegistry = await Artifact.deploy(
        defaultDidRegistryInstance.address,
        _defaultDelegateType
      );
    } else {
      [owner, account1, account2] = lacchain.getSigners();
      Artifact = await ethers.getContractFactory(
        "VerificationRegistryGM",
        owner
      );

      const instance = await lacchain.deployContract(
        Artifact,
        lacchain.baseRelayAddress,
        defaultDidRegistryInstance.address,
        _defaultDelegateType
      );
      verificationRegistry = Artifact.attach(instance.address);
    }

    verificationRegistryAddress = verificationRegistry.address;

    return verificationRegistry.address;
  }

  async function initSigners() {
    if (network.name != "lacchain") {
      [deployer, entity1, entity2, entity3] = await ethers.getSigners();
    } else {
      [deployer, entity1, entity2, entity3] = lacchain.getSigners();
    }
  }

  this.beforeEach(async function () {
    await initSigners();
    await deployVerificationRegistry();
  });

  describe("General validation", () => {
    it("Should set right values on contract deployment", async function () {
      const Artifact = await ethers.getContractFactory(artifactName, entity1);
      const ci = Artifact.attach(verificationRegistryAddress);
      expect(await ci.defaultDelegateType()).to.equal(defaultDelegateType);
      expect(await ci.defaultDidRegistry()).to.equal(
        defaultDidRegistryInstance.address
      );
    });
    it("Should set right values on artifact deployment", async () => {
      await issue(verificationRegistryAddress);
    });
    it("Should throw on setting an invalid expiration time", async () => {
      const message = "some message digest";
      const digest = keccak256(toUtf8Bytes(message));
      const delta = -3600 * 24 * 365;
      const exp = Math.floor(Date.now() / 1000) + delta;
      const Artifact = await ethers.getContractFactory(artifactName, entity1);
      const verificationRegistry = Artifact.attach(verificationRegistryAddress);
      const action = verificationRegistry.issue(digest, exp, entity1.address);
      await handleRevert("IET", action);
    });
    it("Shoud throw on attempting to send a transaction with an unauthorized controller", async () => {
      const message = "some message digest";
      const digest = keccak256(toUtf8Bytes(message));
      const delta = 3600 * 24 * 365;
      const exp = Math.floor(Date.now() / 1000) + delta;
      const Artifact = await ethers.getContractFactory(artifactName, entity1); // entity1 is the address of the sender account
      const verificationRegistry = Artifact.attach(verificationRegistryAddress);
      const action = verificationRegistry.issue(
        digest,
        exp,
        entity2.address // assuming entity2.address is the main entity
      );
      await handleRevert("IC", action);
    });
  });

  describe("Did registry customization methods", () => {
    it("Shoud add a DIDRegistry by signed way", async () => {
      const { didRegistry } = await deployDidRegistry();
      const organization = ethers.Wallet.createRandom();

      await addDidRegistrySigned(didRegistry.address, organization);
    });
    it("Should fail when trying to send an already signed transaction", async () => {
      const { didRegistry } = await deployDidRegistry();
      const organization = ethers.Wallet.createRandom();

      const { v, r, s, nonce } = await addDidRegistrySigned(
        didRegistry.address,
        organization
      );

      // re send
      const attacker = entity2;
      const Artifact = await ethers.getContractFactory(artifactName, attacker);
      const contractInstance = Artifact.attach(verificationRegistryAddress);
      const action = contractInstance.addDidRegistrySigned(
        didRegistry.address,
        nonce,
        v,
        r,
        s
      );
      await handleRevert("IN", action);
    });
    it("Should fail when trying to send a valid already didRegistry", async () => {
      const { didRegistry } = await deployDidRegistry();
      const organization = ethers.Wallet.createRandom();

      const { nonce } = await addDidRegistrySigned(
        didRegistry.address,
        organization
      );

      // re send
      const newNonce = nonce.add(1);
      const { typeDataHash } = await getTypedDataHashForAddDidRegistry(
        didRegistry.address,
        newNonce
      );
      // sign type data hash
      const signingKey = organization._signingKey;
      const newSignature = signingKey().signDigest(typeDataHash);
      // 3. Send Signed Transaction
      const attacker = entity2;
      const Artifact = await ethers.getContractFactory(artifactName, attacker);
      const contractInstance = Artifact.attach(verificationRegistryAddress);
      const action = contractInstance.addDidRegistrySigned(
        didRegistry.address,
        newNonce,
        newSignature.v,
        newSignature.r,
        newSignature.s
      );
      await handleRevert("IDR", action);
    });
    it("Shoud fail to remove a DIDRegistry by signed way when unauthorized", async () => {
      // when removing an attacker will never be able to remove a registry that was registered by another entity,
      // since there are no methods that could give a chance for this threat
    });
    it("Shoud remove a DIDRegistry by signed way", async () => {
      const { didRegistry } = await deployDidRegistry();
      const organization = ethers.Wallet.createRandom();
      await addDidRegistrySigned(didRegistry.address, organization);
      await removeDidRegistrySigned(organization);
    });
    it("Shoud fail to add a deletegate type by signed way when unauthorized", async () => {
      // when removing an attacker will never be able to add a delegate that was registered by another entity,
      // since there are no methods that could give a chance for this threat
    });
    it("Shoud add a delegate type by signed way", async () => {
      const organization = ethers.Wallet.createRandom();
      const customDelegateType = formatBytes32String(
        delegateTypeWithoutPadding
      ); // bytes32 right padded
      await addDelegateTypeSigned(customDelegateType, organization);
    });
    it("Shoud fail to remove a delegate type by signed way when unauthorized", async () => {
      // when removing an attacker will never be able to remove a delegate that was registered by another entity,
      // since there are no methods that could give a chance for this threat
    });
    it("Shoud remove a delegate type by signed way", async () => {
      const organization = ethers.Wallet.createRandom();
      const customDelegateType = formatBytes32String(
        delegateTypeWithoutPadding
      ); // bytes32 right padded
      await addDelegateTypeSigned(customDelegateType, organization);
      await removeDelegateTypeSigned(customDelegateType, organization);
    });
  });

  describe("On Hold methods", () => {
    it("Should set onHold to true on setting a digest in onHold", async () => {
      await issue();
      await toggletOnHold(true);
    });
    it("Should pass on performing onHold on a non issued digest", async () => {
      await toggletOnHold(true);
    });
    it("Should transition from true to false when calling Onhold", async () => {
      await toggletOnHold(true);
      await toggletOnHold(false);
    });
    it("Shoud fail to toggle onHold status by signed way when unauthorized", async () => {
      const organization = ethers.Wallet.createRandom();
      const message = "someMessage";
      const status = true;
      const digest = keccak256(toUtf8Bytes(message));
      const nonce = 0;
      const { typeDataHash } = await getTypedDataHashForOnHoldType(
        digest,
        organization.address,
        status,
        nonce
      );
      // sign type data hash
      const attacker = ethers.Wallet.createRandom();
      const signingKey = attacker._signingKey;
      const { v, r, s } = signingKey().signDigest(typeDataHash);
      // 3. Send Signed Transaction
      const anySender = entity3;
      const Artifact = await ethers.getContractFactory(artifactName, anySender);
      const contractInstance = Artifact.attach(verificationRegistryAddress);

      const action = contractInstance.onHoldChangeSigned(
        digest,
        organization.address,
        status,
        nonce,
        v,
        r,
        s
      );
      await handleRevert("IC", action);
    });
    it("Shoud toggle on Hold by signed way", async () => {
      const message = "someMessage";
      const organization = ethers.Wallet.createRandom();
      const nonce = 0;
      await addOnHoldSigned(message, organization, true, nonce);
    });
    it("Shoud fail to toggle onHold status by signed way by delegate when unauthorized", async () => {});
    it("Shoud toggle on Hold by delegate by signed way", async () => {
      const message = "someMessage";
      const organization = entity1;
      const delegate = ethers.Wallet.createRandom();
      await authorizeDelegate(delegate.address, organization);
      const status = true;
      await addOnHoldByDelegateSigned(
        message,
        organization.address,
        status,
        delegate
      );
    });
    it("Shoud fail to toggle onHold status by signed way by delegate with custom type when unauthorized", async () => {
      const message = "someMessage";
      const organization = entity1;
      const organizationAddress = organization.address;
      const nonce = 0;
      const attacker = ethers.Wallet.createRandom();
      const status = true;
      const digest = keccak256(toUtf8Bytes(message));
      const { typeDataHash } = await getTypedDataHashForOnHoldType(
        digest,
        organizationAddress,
        status,
        nonce
      );
      // sign type data hash
      const signingKey = attacker._signingKey;
      const { v, r, s } = signingKey().signDigest(typeDataHash);
      // 3. Send Signed Transaction
      const anySender = entity3;
      const Artifact = await ethers.getContractFactory(artifactName, anySender);
      const contractInstance = Artifact.attach(verificationRegistryAddress);

      const action = contractInstance.onHoldByDelegateSigned(
        digest,
        organizationAddress,
        status,
        nonce,
        v,
        r,
        s
      );
      await handleRevert("ID", action);
    });
    it("Shoud fail to toggle onHold status when sending with the same nonce by the same account", async () => {
      const message = "someMessage";
      const organization = entity1;
      const status = true;
      const delegate = ethers.Wallet.createRandom();
      await authorizeDelegate(delegate.address, organization);

      const { nonce } = await addOnHoldByDelegateSigned(
        message,
        organization.address,
        status,
        delegate
      );

      const organizationAddress = organization.address;

      const digest = keccak256(toUtf8Bytes(message));
      const { typeDataHash } = await getTypedDataHashForOnHoldType(
        digest,
        organizationAddress,
        status,
        nonce
      );
      // sign type data hash
      const signingKey = delegate._signingKey;
      const { v, r, s } = signingKey().signDigest(typeDataHash);
      // 3. Send Signed Transaction
      const anySender = entity3;
      const Artifact = await ethers.getContractFactory(artifactName, anySender);
      const contractInstance = Artifact.attach(verificationRegistryAddress);

      const action = contractInstance.onHoldByDelegateSigned(
        digest,
        organizationAddress,
        status,
        nonce,
        v,
        r,
        s
      );
      await handleRevert("IN", action);
    });
    it("Shoud toggle on Hold by delegate by signed way with custom type", async () => {
      const message = "someMessage";
      const organization = entity1;
      const customDelegateType = formatBytes32String(
        delegateTypeWithoutPadding
      ); // bytes32 right padded

      const delegate = ethers.Wallet.createRandom();
      await authorizeDelegate(delegate.address, organization); // authorize delegate in DID registry
      await setCustomDelegateType(organization, customDelegateType); // set a delagate type in verification registry

      const status = true;

      await addOnHoldByDelegateWithCustomTypeSigned(
        customDelegateType,
        message,
        organization.address,
        status,
        delegate
      );
    });

    it("Shoud failt to toggle on Hold by delegate by signed way with custom type when nonce already used", async () => {
      const message = "someMessage";
      const organization = entity1;
      const customDelegateType = formatBytes32String(
        delegateTypeWithoutPadding
      ); // bytes32 right padded

      const delegate = ethers.Wallet.createRandom();
      await authorizeDelegate(delegate.address, organization); // authorize delegate in DID registry
      await setCustomDelegateType(organization, customDelegateType); // set a delagate type in verification registry

      const status = true;

      const { v, r, s, nonce } = await addOnHoldByDelegateWithCustomTypeSigned(
        customDelegateType,
        message,
        organization.address,
        status,
        delegate
      );

      const organizationAddress = organization.address;
      const digest = keccak256(toUtf8Bytes(message));
      // 3. Send Signed Transaction
      const anySender = entity3;
      const Artifact = await ethers.getContractFactory(artifactName, anySender);
      const contractInstance = Artifact.attach(verificationRegistryAddress);

      const action = contractInstance.onHoldByDelegateWithCustomTypeSigned(
        customDelegateType,
        organizationAddress,
        digest,
        status,
        nonce,
        v,
        r,
        s
      );
      await handleRevert("IN", action);
    });
  });

  describe("Issuance methods", () => {
    it("Should issue", async () => {
      const message = "some message";
      await issue(verificationRegistryAddress, message);
    });
    it("Should issue by delegate", async () => {
      const organization = entity1;
      const delegate = entity2;
      await authorizeDelegate(delegate.address, organization);
      await issueByDelegate(
        verificationRegistryAddress,
        "some message",
        3600 * 24 * 365,
        organization,
        delegate
      );
    });
    it("Should throw on issuing with an unauthorized delegate", async () => {
      const message = "some message";
      const delta = 3600 * 24 * 365;
      const digest = keccak256(toUtf8Bytes(message));
      const exp = Math.floor(Date.now() / 1000) + delta;
      const Artifact = await ethers.getContractFactory(artifactName, entity1);
      const verificationRegistry = Artifact.attach(verificationRegistryAddress);
      const action = verificationRegistry.issueByDelegate(
        entity2.address,
        digest,
        exp
      );
      await handleRevert("ID", action);
    });
    it("Should issue by delegate with custom type", async () => {
      const customDelegateType =
        "0x0be0ff6adc81f13f4d66a7dbb4cd4b6018141f5d65f53b245681255a1d2667f5";
      const organization = entity1;
      const delegate = entity2;
      await setCustomDelegateType(organization, customDelegateType);
      await authorizeDelegate(
        delegate.address,
        organization,
        defaultDidRegistryInstance.address,
        customDelegateType
      );
      await issueByDelegateWithCustomType(
        customDelegateType,
        verificationRegistryAddress,
        "some message",
        3600 * 24 * 365,
        organization,
        delegate
      );
    });
    it("Should issue by delegate with custom delegate type and custom didRegistry", async () => {
      const result = await deployDidRegistry();
      const customDidRegistry = result.didRegistry;
      const organization = entity1;
      await addCustomDidRegistry(customDidRegistry.address, organization);
      const customDelegateType =
        "0x0be0ff6adc81f13f4d66a7dbb4cd4b6018141f5d65f53b245681255a1d2667f5";
      const delegate = entity2;
      await setCustomDelegateType(organization, customDelegateType);
      await authorizeDelegate(
        delegate.address,
        organization,
        customDidRegistry.address,
        customDelegateType
      );
      await issueByDelegateWithCustomType(
        customDelegateType,
        verificationRegistryAddress,
        "some message",
        3600 * 24 * 365,
        organization,
        delegate
      );
    });
    it("Should throw on issuing with an invalid custom type", async () => {
      const organization = entity1;
      const customDelegateType =
        "0x0be0ff6adc81f13f4d66a7dbb4cd4b6018141f5d65f53b245681255a1d2667f5";
      const delegate = entity2;
      await authorizeDelegate(delegate.address, organization); // authorizing delegate with the default delegate type

      const message = "some message";
      const delta = 3600 * 24 * 365;
      const digest = keccak256(toUtf8Bytes(message));
      const exp = Math.floor(Date.now() / 1000) + delta;

      const Artifact = await ethers.getContractFactory(artifactName, delegate);
      const verificationRegistry = Artifact.attach(verificationRegistryAddress);
      const action = verificationRegistry.issueByDelegateWithCustomType(
        customDelegateType,
        organization.address,
        digest,
        exp
      );

      await handleRevert("DTNS", action);
    });

    it("Should throw on issuing an already issued digest by the same entity", async () => {
      const message = "some message digest";
      const digest = keccak256(toUtf8Bytes(message));
      const delta = 3600 * 24 * 365;
      const exp = Math.floor(Date.now() / 1000) + delta;
      const Artifact = await ethers.getContractFactory(artifactName, entity1);
      const verificationRegistry = Artifact.attach(verificationRegistryAddress);
      await issue(verificationRegistryAddress, message, delta, entity1);
      const action = verificationRegistry.issue(digest, exp, entity1.address);
      await handleRevert("RAE", action);
    });
    it("Should issue by signed way", async () => {
      const organization = ethers.Wallet.createRandom();
      await issueSigned(organization);
    });
    it("Should throw on attempting to issue signed with an invalid signature", async () => {
      const organization = ethers.Wallet.createRandom();
      const { typeDataHash, digest, exp } = await getTypedDataHashForIssue(
        organization.address
      );
      // sign type data hash
      const impersonator = ethers.Wallet.createRandom();
      const signingKey = impersonator._signingKey;
      const { v, r, s } = signingKey().signDigest(typeDataHash);
      // 3. Send Signed Transaction
      const anySender = entity3;
      const Artifact = await ethers.getContractFactory(artifactName, anySender);
      const contractInstance = Artifact.attach(verificationRegistryAddress);
      const action = contractInstance.issueSigned(
        digest,
        exp,
        organization.address,
        v,
        r,
        s
      );
      await handleRevert("IC", action);
    });
    it("Should issue by delegate by signed way", async () => {
      const organization = entity1;
      const delegate = ethers.Wallet.createRandom();
      await authorizeDelegate(delegate.address, organization);
      await issueByDelegateSigned(organization, delegate);
    });
    it("Should issue by delegate with custom type by signed way", async () => {
      const customDelegateType =
        "0x0be0ff6adc81f13f4d66a7dbb4cd4b6018141f5d65f53b245681255a1d2667f5";
      const organization = entity1;
      const delegate = ethers.Wallet.createRandom();
      await setCustomDelegateType(organization, customDelegateType);
      await authorizeDelegate(
        delegate.address,
        organization,
        defaultDidRegistryInstance.address,
        customDelegateType
      );
      await issueByDelegateWithCustomDelegateTypeSigned(
        customDelegateType,
        organization.address,
        delegate
      );
    });
  });

  describe("Revocation methods", () => {
    it("Should return expected values on revoking a previously issued digest", async () => {
      const message = "some message";
      const delta = 3600 * 24 * 365;
      await issue(verificationRegistryAddress, "some message", delta, entity1);
      const expectedNonce = 2;
      await revoke(
        verificationRegistryAddress,
        message,
        entity1,
        expectedNonce
      );
    });
    it("Should revoke by delegate", async () => {
      const organization = entity1;
      const delegate = entity2;
      await authorizeDelegate(delegate.address, organization);
      await revokeByDelegate(
        verificationRegistryAddress,
        "some message",
        organization,
        delegate
      );
    });
    it("Should revoke by delegate with custom type", async () => {
      const customDelegateType =
        "0x0be0ff6adc81f13f4d66a7dbb4cd4b6018141f5d65f53b245681255a1d2667f5";
      const organization = entity1;
      const delegate = entity2;
      await setCustomDelegateType(organization, customDelegateType);
      await authorizeDelegate(
        delegate.address,
        organization,
        defaultDidRegistryInstance.address,
        customDelegateType
      );
      await revokeByDelegateWithCustomType(
        customDelegateType,
        verificationRegistryAddress,
        "some message",
        organization,
        delegate
      );
    });
    it("Should revoke by signed way", async () => {
      const organization = ethers.Wallet.createRandom();
      await revokeSigned(organization);
    });
    it("Should revoke by delegate by signed way", async () => {
      const organization = entity1;
      const delegate = ethers.Wallet.createRandom();
      await authorizeDelegate(delegate.address, organization);
      await revokeByDelegateSigned(organization, delegate);
    });
    it("Should revoke by delegate with custom type by signed way", async () => {
      const customDelegateType =
        "0x0be0ff6adc81f13f4d66a7dbb4cd4b6018141f5d65f53b245681255a1d2667f5";
      const organization = entity1;
      const delegate = ethers.Wallet.createRandom();
      await setCustomDelegateType(organization, customDelegateType);
      await authorizeDelegate(
        delegate.address,
        organization,
        defaultDidRegistryInstance.address,
        customDelegateType
      );
      await revokeByDelegateWithCustomDelegateTypeSigned(
        customDelegateType,
        organization.address,
        delegate
      );
    });
    it("Should revoke by delegate with custom did registry and custom delegate type", async () => {
      const customDidRegistry = await deployDidRegistry();
      const organization = entity1;
      await addCustomDidRegistry(
        customDidRegistry.didRegistry.address,
        organization
      );
      const customDelegateType =
        "0x0be0ff6adc81f13f4d66a7dbb4cd4b6018141f5d65f53b245681255a1d2667f5";
      const delegate = ethers.Wallet.createRandom();
      await setCustomDelegateType(organization, customDelegateType);
      await authorizeDelegate(
        delegate.address,
        organization,
        customDidRegistry.didRegistry.address,
        customDelegateType
      );
      await revokeByDelegateWithCustomDelegateTypeSigned(
        customDelegateType,
        organization.address,
        delegate
      );
    });
  });

  describe("Update methods", () => {
    it("Should update", async () => {
      const organization = entity1;
      const Artifact = await ethers.getContractFactory(
        artifactName,
        organization
      );
      const contractInstance = Artifact.attach(verificationRegistryAddress);
      const message = "some message";
      const digest = keccak256(toUtf8Bytes(message));
      await issue(verificationRegistryAddress, message);
      const delta = 3600 * 24 * 2;
      const exp = Math.floor(Date.now() / 1000) + delta;
      const result = await contractInstance.update(
        digest,
        exp,
        organization.address
      );
      await expect(result)
        .to.emit(contractInstance, "NewUpdate")
        .withArgs(digest, organization.address, exp);
    });

    it("Should update by signed way", async () => {
      const organization = ethers.Wallet.createRandom();
      await issueSigned(organization);
      await updateSigned(organization);
    });
    it("Should update by delegate", async () => {
      const organization = entity1;
      const delegate = entity2;
      await authorizeDelegate(delegate.address, organization);
      const message = "some message";
      await issue(verificationRegistryAddress, message);
      await updateByDelegate(
        verificationRegistryAddress,
        message,
        3600 * 24 * 365,
        organization,
        delegate
      );
    });
  });
});

async function handleRevert(revertMessage: string, action: any) {
  if (network.name != "lacchain") {
    await expect(action).to.be.revertedWith(revertMessage);
  } else {
    try {
      const tx = await action;
      tx.wait(); // shoud fail here
      throw new Error(unexpectedErrorMessage); // should never reach here, if so then contract logic is incorrect
    } catch (error: any) {
      if (error.message == unexpectedErrorMessage) {
        throw new Error(unexpectedErrorMessage);
      }
    }
  }
}

async function issue(
  _verificationRegistryAddress = verificationRegistryAddress,
  message = genericMessage,
  delta = 3600 * 24 * 365,
  sender = entity1
) {
  const digest = keccak256(toUtf8Bytes(message));
  const exp = Math.floor(Date.now() / 1000) + delta;
  const Artifact = await ethers.getContractFactory(artifactName, sender);
  const verificationRegistry = Artifact.attach(_verificationRegistryAddress);
  const result = await verificationRegistry.issue(digest, exp, sender.address);
  await expect(result)
    .to.emit(verificationRegistry, "NewIssuance")
    .withArgs(digest, sender.address, anyValue, exp);
  const q = await verificationRegistry.getDetails(sender.address, digest);
  expect(q.exp).to.equal(exp);
  expect(q.onHold).to.equal(false);
  expect(q.isRevoked).to.equal(false);
  expect(q.nonce).to.equal(1);
}

async function revoke(
  _verificationRegistryAddress = verificationRegistryAddress,
  message = genericMessage,
  sender = entity1,
  expectedNonce = 0
) {
  const digest = keccak256(toUtf8Bytes(message));
  const Artifact = await ethers.getContractFactory(artifactName, sender);
  const verificationRegistry = Artifact.attach(_verificationRegistryAddress);
  const result = await verificationRegistry.revoke(digest, sender.address);
  await expect(result)
    .to.emit(verificationRegistry, "NewRevocation")
    .withArgs(digest, sender.address, anyValue, anyValue);
  const details = await verificationRegistry.getDetails(sender.address, digest);
  expect(details.isRevoked).to.equal(true);
  expect(details.exp).to.be.greaterThan(0);
  expect(details.nonce).to.eq(expectedNonce);
}

async function toggletOnHold(
  expected: boolean,
  _verificationRegistryAddress = verificationRegistryAddress,
  message = genericMessage,
  sender = entity1
) {
  const digest = keccak256(toUtf8Bytes(message));
  const Artifact = await ethers.getContractFactory(artifactName, sender);
  const verificationRegistry = Artifact.attach(_verificationRegistryAddress);
  const result = await verificationRegistry.onHoldChange(
    digest,
    sender.address,
    expected
  );
  await expect(result)
    .to.emit(verificationRegistry, "NewOnHoldChange")
    .withArgs(digest, sender.address, expected, anyValue);
  const q = await verificationRegistry.getDetails(sender.address, digest);
  expect(q.onHold).to.equal(expected);
}

async function issueByDelegate(
  _verificationRegistryAddress = verificationRegistryAddress,
  message = genericMessage,
  delta = 3600 * 24 * 365,
  organization = entity1,
  delegate = entity2
) {
  const digest = keccak256(toUtf8Bytes(message));
  const exp = Math.floor(Date.now() / 1000) + delta;
  const Artifact = await ethers.getContractFactory(artifactName, delegate);
  const verificationRegistry = Artifact.attach(_verificationRegistryAddress);
  const result = await verificationRegistry.issueByDelegate(
    organization.address,
    digest,
    exp
  );
  await expect(result)
    .to.emit(verificationRegistry, "NewIssuance")
    .withArgs(digest, organization.address, anyValue, exp);
  const q = await verificationRegistry.getDetails(organization.address, digest);
  expect(q.exp).to.equal(exp);
  expect(q.onHold).to.equal(false);
}

async function updateByDelegate(
  _verificationRegistryAddress = verificationRegistryAddress,
  message = genericMessage,
  delta = 3600 * 24 * 365,
  organization = entity1,
  delegate = entity2
) {
  const Artifact = await ethers.getContractFactory(artifactName, delegate);
  const verificationRegistry = Artifact.attach(_verificationRegistryAddress);
  const digest = keccak256(toUtf8Bytes(message));
  const details = await verificationRegistry.getDetails(
    organization.address,
    digest
  );
  const nonce = details.nonce;
  const exp = Math.floor(Date.now() / 1000) + delta;
  const result = await verificationRegistry.updateByDelegate(
    digest,
    exp,
    organization.address
  );
  await expect(result)
    .to.emit(verificationRegistry, "NewUpdate")
    .withArgs(digest, organization.address, exp);
  const q = await verificationRegistry.getDetails(organization.address, digest);
  expect(q.exp).to.equal(exp);
  expect(q.onHold).to.equal(false);
  expect(q.nonce).to.equal(nonce.add(1));
}

async function issueByDelegateWithCustomType(
  customDelegateType: string,
  _verificationRegistryAddress = verificationRegistryAddress,
  message = genericMessage,
  delta = 3600 * 24 * 365,
  organization = entity1,
  delegate = entity2
) {
  const digest = keccak256(toUtf8Bytes(message));
  const exp = Math.floor(Date.now() / 1000) + delta;
  const Artifact = await ethers.getContractFactory(artifactName, delegate);
  const verificationRegistry = Artifact.attach(_verificationRegistryAddress);
  const result = await verificationRegistry.issueByDelegateWithCustomType(
    customDelegateType,
    organization.address,
    digest,
    exp
  );
  await expect(result)
    .to.emit(verificationRegistry, "NewIssuance")
    .withArgs(digest, organization.address, anyValue, exp);
  const q = await verificationRegistry.getDetails(organization.address, digest);
  expect(q.exp).to.equal(exp);
  expect(q.onHold).to.equal(false);
}

async function authorizeDelegate(
  delegateAddress: string,
  organization: SignerWithAddress | GasModelSignerModified,
  didRegistryAddress = defaultDidRegistryInstance.address,
  delegateType = defaultDelegateType
) {
  const Artifact = await ethers.getContractFactory(
    didRegistryArtifactName,
    organization
  );
  const didRegistryOrg = Artifact.attach(didRegistryAddress);
  await didRegistryOrg.addDelegate(
    organization.address,
    delegateType,
    delegateAddress,
    3600 * 24 * 365
  );

  const d = await didRegistryOrg.validDelegate(
    organization.address,
    delegateType,
    delegateAddress
  );
  expect(d).to.equal(true);
}

async function setCustomDelegateType(
  organization: SignerWithAddress | GasModelSignerModified,
  customDelegateType: string
) {
  const Artifact = await ethers.getContractFactory(artifactName, organization);
  const ci = Artifact.attach(verificationRegistryAddress);
  const result = await ci.addDelegateType(customDelegateType);
  await expect(result)
    .to.emit(ci, "NewDelegateTypeChange")
    .withArgs(customDelegateType, organization.address, true);
}

async function addCustomDidRegistry(
  customDidRegistryAddress: string,
  organization: SignerWithAddress | GasModelSignerModified,
  _verificationRegistryAddress = verificationRegistryAddress
) {
  const Artifact = await ethers.getContractFactory(artifactName, organization);
  const verificationRegistryOrg = Artifact.attach(_verificationRegistryAddress);
  const result = await verificationRegistryOrg.addDidRegistry(
    customDidRegistryAddress
  );
  await expect(result)
    .to.emit(verificationRegistryOrg, "DidRegistryChange")
    .withArgs(
      organization.address,
      ethers.constants.AddressZero,
      customDidRegistryAddress
    );
}

async function revokeByDelegate(
  _verificationRegistryAddress = verificationRegistryAddress,
  message = genericMessage,
  organization = entity1,
  delegate = entity2
) {
  const digest = keccak256(toUtf8Bytes(message));
  const Artifact = await ethers.getContractFactory(artifactName, delegate);
  const verificationRegistry = Artifact.attach(_verificationRegistryAddress);
  const result = await verificationRegistry.revokeByDelegate(
    organization.address,
    digest
  );
  await expect(result)
    .to.emit(verificationRegistry, "NewRevocation")
    .withArgs(digest, organization.address, anyValue, anyValue);
}

async function revokeByDelegateWithCustomType(
  customDelegateType: string,
  _verificationRegistryAddress = verificationRegistryAddress,
  message = genericMessage,
  organization = entity1,
  delegate = entity2
) {
  const digest = keccak256(toUtf8Bytes(message));
  const Artifact = await ethers.getContractFactory(artifactName, delegate);
  const verificationRegistry = Artifact.attach(_verificationRegistryAddress);
  const result = await verificationRegistry.revokeByDelegateWithCustomType(
    customDelegateType,
    organization.address,
    digest
  );
  await expect(result)
    .to.emit(verificationRegistry, "NewRevocation")
    .withArgs(digest, organization.address, anyValue, anyValue);
}

async function issueSigned(
  organization: Wallet,
  contractName = EIP712ContractName,
  message = "some message",
  delta = 3600 * 24 * 365,
  chainId = network.config.chainId,
  anySender = entity2
) {
  const { typeDataHash, digest, exp } = await getTypedDataHashForIssue(
    organization.address,
    contractName,
    message,
    delta,
    chainId
  );
  // sign type data hash
  const signingKey = organization._signingKey;
  const { v, r, s } = signingKey().signDigest(typeDataHash);

  // 3. Send Signed Transaction
  const Artifact = await ethers.getContractFactory(artifactName, anySender);
  const contractInstance = Artifact.attach(verificationRegistryAddress);
  const result = await contractInstance.issueSigned(
    digest,
    exp,
    organization.address,
    v,
    r,
    s
  );
  await expect(result)
    .to.emit(contractInstance, "NewIssuance")
    .withArgs(digest, organization.address, anyValue, exp);
  const q = await contractInstance.getDetails(organization.address, digest);
  expect(q.exp).to.equal(exp);
  expect(q.onHold).to.equal(false);
}

async function updateSigned(
  organization: Wallet,
  contractName = EIP712ContractName,
  message = "some message",
  delta = 3600 * 24 * 365,
  chainId = network.config.chainId,
  anySender = entity2
) {
  const Artifact = await ethers.getContractFactory(artifactName, anySender);
  const contractInstance = Artifact.attach(verificationRegistryAddress);
  const _digest = keccak256(toUtf8Bytes(message));
  const digestDetails = await contractInstance.getDetails(
    organization.address,
    _digest
  );
  const nonce = digestDetails.nonce;
  const { typeDataHash, digest, exp } = await getTypedDataHashForUpdate(
    organization.address,
    nonce,
    contractName,
    message,
    delta,
    chainId
  );
  // sign type data hash
  const signingKey = organization._signingKey;
  const { v, r, s } = signingKey().signDigest(typeDataHash);

  // 3. Send Signed Transaction
  const result = await contractInstance.updateSigned(
    digest,
    exp,
    organization.address,
    nonce,
    v,
    r,
    s
  );
  await expect(result)
    .to.emit(contractInstance, "NewUpdate")
    .withArgs(digest, organization.address, exp);
  const q = await contractInstance.getDetails(organization.address, digest);
  expect(q.exp).to.equal(exp);
  expect(q.onHold).to.equal(false);
  expect(q.nonce).to.equal(nonce.add(1));
}

async function revokeSigned(
  organization: Wallet,
  contractName = EIP712ContractName,
  message = "some message",
  anySender = entity2
) {
  const { typeDataHash, digest } = await getTypedDataHashForRevocation(
    organization.address,
    contractName,
    message
  );
  // sign type data hash
  const signingKey = organization._signingKey;
  const { v, r, s } = signingKey().signDigest(typeDataHash);

  // 3. Send Signed Transaction
  const Artifact = await ethers.getContractFactory(artifactName, anySender);
  const contractInstance = Artifact.attach(verificationRegistryAddress);
  const result = await contractInstance.revokeSigned(
    digest,
    organization.address,
    v,
    r,
    s
  );
  await expect(result)
    .to.emit(contractInstance, "NewRevocation")
    .withArgs(digest, organization.address, anyValue, anyValue);
}

async function issueByDelegateSigned(
  organization: SignerWithAddress | GasModelSignerModified,
  delegate: Wallet,
  contractName = EIP712ContractName,
  message = "some message",
  delta = 3600 * 24 * 365,
  chainId = network.config.chainId,
  anySender = entity2
) {
  const { typeDataHash, digest, exp } = await getTypedDataHashForIssue(
    organization.address,
    contractName,
    message,
    delta,
    chainId
  );
  // sign type data hash
  const signingKey = delegate._signingKey;
  const { v, r, s } = signingKey().signDigest(typeDataHash);

  // 3. Send Signed Transaction
  const Artifact = await ethers.getContractFactory(artifactName, anySender);
  const contractInstance = Artifact.attach(verificationRegistryAddress);
  const result = await contractInstance.issueByDelegateSigned(
    digest,
    exp,
    organization.address,
    v,
    r,
    s
  );
  await expect(result)
    .to.emit(contractInstance, "NewIssuance")
    .withArgs(digest, organization.address, anyValue, exp);
  const q = await contractInstance.getDetails(organization.address, digest);
  expect(q.exp).to.equal(exp);
  expect(q.onHold).to.equal(false);
}

async function revokeByDelegateSigned(
  organization: SignerWithAddress | GasModelSignerModified,
  delegate: Wallet,
  contractName = EIP712ContractName,
  message = "some message",
  anySender = entity2
) {
  const { typeDataHash, digest } = await getTypedDataHashForRevocation(
    organization.address,
    contractName,
    message
  );
  // sign type data hash
  const signingKey = delegate._signingKey;
  const { v, r, s } = signingKey().signDigest(typeDataHash);

  // 3. Send Signed Transaction
  const Artifact = await ethers.getContractFactory(artifactName, anySender);
  const contractInstance = Artifact.attach(verificationRegistryAddress);
  const result = await contractInstance.revokeByDelegateSigned(
    digest,
    organization.address,
    v,
    r,
    s
  );
  await expect(result)
    .to.emit(contractInstance, "NewRevocation")
    .withArgs(digest, organization.address, anyValue, anyValue);
}

async function issueByDelegateWithCustomDelegateTypeSigned(
  delegateType: string,
  organizationAddress: string,
  delegate: Wallet,
  contractName = EIP712ContractName,
  message = "some message",
  delta = 3600 * 24 * 365,
  chainId = network.config.chainId,
  anySender = entity2
) {
  const { typeDataHash, digest, exp } = await getTypedDataHashForIssue(
    organizationAddress,
    contractName,
    message,
    delta,
    chainId
  );
  // sign type data hash
  const signingKey = delegate._signingKey;
  const { v, r, s } = signingKey().signDigest(typeDataHash);

  // 3. Send Signed Transaction
  const Artifact = await ethers.getContractFactory(artifactName, anySender);
  const contractInstance = Artifact.attach(verificationRegistryAddress);
  const result =
    await contractInstance.issueByDelegateWithCustomDelegateTypeSigned(
      delegateType,
      digest,
      exp,
      organizationAddress,
      v,
      r,
      s
    );
  await expect(result)
    .to.emit(contractInstance, "NewIssuance")
    .withArgs(digest, organizationAddress, anyValue, exp);
  const q = await contractInstance.getDetails(organizationAddress, digest);
  expect(q.exp).to.equal(exp);
  expect(q.onHold).to.equal(false);
}

async function revokeByDelegateWithCustomDelegateTypeSigned(
  delegateType: string,
  organizationAddress: string,
  delegate: Wallet,
  contractName = EIP712ContractName,
  message = "some message",
  anySender = entity2
) {
  const { typeDataHash, digest } = await getTypedDataHashForRevocation(
    organizationAddress,
    contractName,
    message
  );
  // sign type data hash
  const signingKey = delegate._signingKey;
  const { v, r, s } = signingKey().signDigest(typeDataHash);

  // 3. Send Signed Transaction
  const Artifact = await ethers.getContractFactory(artifactName, anySender);
  const contractInstance = Artifact.attach(verificationRegistryAddress);
  const result =
    await contractInstance.revokeByDelegateWithCustomDelegateTypeSigned(
      delegateType,
      digest,
      organizationAddress,
      v,
      r,
      s
    );
  await expect(result)
    .to.emit(contractInstance, "NewRevocation")
    .withArgs(digest, organizationAddress, anyValue, anyValue);
}

async function getTypedDataHashForIssue(
  organizationAddress: String,
  contractName = EIP712ContractName,
  message = "some message",
  delta = 3600 * 24 * 365,
  chainId = network.config.chainId,
  version = contractVersion
): Promise<{ typeDataHash: string; digest: string; exp: number }> {
  const ISSUE_TYPEHASH = keccak256(
    toUtf8Bytes("Issue(bytes32 digest,uint256 exp,address identity)")
  );

  // 0. Build digest
  const digest = keccak256(toUtf8Bytes(message));

  // 1. Build struct data hash
  const exp = Math.floor(Date.now() / 1000) + delta;
  const encodedMessage = defaultAbiCoder.encode(
    ["bytes32", "bytes32", "uint256", "address"],
    [ISSUE_TYPEHASH, digest, exp, organizationAddress]
  );
  const structHash = keccak256(arrayify(encodedMessage)); // OK

  // 2. EIP712
  // 2.1 build domainSeparator
  const TYPE_HASH = keccak256(
    toUtf8Bytes(
      "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    )
  );
  const _hashedName = keccak256(toUtf8Bytes(contractName));
  const _hashedVersion = keccak256(toUtf8Bytes(version));

  const contractAddress = verificationRegistryAddress;
  const eds = defaultAbiCoder.encode(
    ["bytes32", "bytes32", "bytes32", "uint256", "address"],
    [TYPE_HASH, _hashedName, _hashedVersion, chainId, contractAddress]
  );
  const domainSeparator = keccak256(eds); // OK

  // 2.2 Build type data hash
  // Inputs: structHash and domainSeparator
  const typeData = ethers.utils.solidityPack(
    ["bytes1", "bytes1", "bytes32", "bytes32"],
    [0x19, 0x01, domainSeparator, structHash]
  );
  const typeDataHash = keccak256(typeData);
  return { typeDataHash, exp, digest };
}

async function getTypedDataHashForUpdate(
  organizationAddress: String,
  nonce: number | BigNumber,
  contractName = EIP712ContractName,
  message = "some message",
  delta = 3600 * 24 * 365,
  chainId = network.config.chainId,
  version = contractVersion
): Promise<{ typeDataHash: string; digest: string; exp: number }> {
  const UPDATE_TYPEHASH = keccak256(
    toUtf8Bytes(
      "Update(bytes32 digest,uint256 exp,address identity,uint64 nonce)"
    )
  );

  // 0. Build digest
  const digest = keccak256(toUtf8Bytes(message));

  // 1. Build struct data hash
  const exp = Math.floor(Date.now() / 1000) + delta;
  const encodedMessage = defaultAbiCoder.encode(
    ["bytes32", "bytes32", "uint256", "address", "uint64"],
    [UPDATE_TYPEHASH, digest, exp, organizationAddress, nonce]
  );
  const structHash = keccak256(arrayify(encodedMessage)); // OK

  // 2. EIP712
  // 2.1 build domainSeparator
  const TYPE_HASH = keccak256(
    toUtf8Bytes(
      "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    )
  );
  const _hashedName = keccak256(toUtf8Bytes(contractName));
  const _hashedVersion = keccak256(toUtf8Bytes(version));

  const contractAddress = verificationRegistryAddress;
  const eds = defaultAbiCoder.encode(
    ["bytes32", "bytes32", "bytes32", "uint256", "address"],
    [TYPE_HASH, _hashedName, _hashedVersion, chainId, contractAddress]
  );
  const domainSeparator = keccak256(eds); // OK

  // 2.2 Build type data hash
  // Inputs: structHash and domainSeparator
  const typeData = ethers.utils.solidityPack(
    ["bytes1", "bytes1", "bytes32", "bytes32"],
    [0x19, 0x01, domainSeparator, structHash]
  );
  const typeDataHash = keccak256(typeData);
  return { typeDataHash, exp, digest };
}

async function getTypedDataHashForRevocation(
  organizationAddress: string,
  contractName = EIP712ContractName,
  message = "some message"
): Promise<{ typeDataHash: string; digest: string }> {
  const ISSUE_TYPEHASH = keccak256(
    toUtf8Bytes("Revoke(bytes32 digest,address identity)")
  );
  // 0. Build digest
  const digest = keccak256(toUtf8Bytes(message));

  // 1. Build struct data hash
  const encodedMessage = defaultAbiCoder.encode(
    ["bytes32", "bytes32", "address"],
    [ISSUE_TYPEHASH, digest, organizationAddress]
  );
  const structHash = keccak256(arrayify(encodedMessage));

  const domainSeparator = await getDomainSeparator(contractName);
  // 2.2 Build type data hash
  // Inputs: structHash and domainSeparator
  const typeData = ethers.utils.solidityPack(
    ["bytes1", "bytes1", "bytes32", "bytes32"],
    [0x19, 0x01, domainSeparator, structHash]
  );
  const typeDataHash = keccak256(typeData);
  return { typeDataHash, digest };
}

async function getTypedDataHashForAddDidRegistry(
  didRegistryAddressCandidate: string,
  nonce: number | BigNumber,
  contractName = EIP712ContractName,
  chainId = network.config.chainId,
  version = contractVersion
): Promise<{ typeDataHash: string }> {
  const ADD_DID_REGISTRY_TYPEHASH = keccak256(
    toUtf8Bytes("AddDidRegistry(address didRegistryAddress,uint64 nonce)")
  );

  // 0. Build digest
  // const digest = keccak256(toUtf8Bytes(message));

  // 1. Build struct data hash
  const encodedMessage = defaultAbiCoder.encode(
    ["bytes32", "address", "uint64"],
    [ADD_DID_REGISTRY_TYPEHASH, didRegistryAddressCandidate, nonce]
  );
  const structHash = keccak256(arrayify(encodedMessage)); // OK

  // 2. EIP712
  // 2.1 build domainSeparator
  const TYPE_HASH = keccak256(
    toUtf8Bytes(
      "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    )
  );
  const _hashedName = keccak256(toUtf8Bytes(contractName));
  const _hashedVersion = keccak256(toUtf8Bytes(version));

  const contractAddress = verificationRegistryAddress;
  const eds = defaultAbiCoder.encode(
    ["bytes32", "bytes32", "bytes32", "uint256", "address"],
    [TYPE_HASH, _hashedName, _hashedVersion, chainId, contractAddress]
  );
  const domainSeparator = keccak256(eds); // OK

  // 2.2 Build type data hash
  // Inputs: structHash and domainSeparator
  const typeData = ethers.utils.solidityPack(
    ["bytes1", "bytes1", "bytes32", "bytes32"],
    [0x19, 0x01, domainSeparator, structHash]
  );
  const typeDataHash = keccak256(typeData);
  return { typeDataHash };
}

async function getTypedDataHashForAddDelegateType(
  delegateType: string,
  nonce: number | BigNumber
): Promise<{ typeDataHash: string }> {
  const ADD_DELEGATE_TYPEHASH = keccak256(
    toUtf8Bytes("AddDelegateType(bytes32 delegateType,uint64 nonce)")
  );

  // 1. Build struct data hash
  const encodedMessage = defaultAbiCoder.encode(
    ["bytes32", "bytes32", "uint64"],
    [ADD_DELEGATE_TYPEHASH, delegateType, nonce]
  );

  const typeDataHash = await getTypedDataHash(encodedMessage);
  return typeDataHash;
}

async function getTypedDataHashForOnHoldType(
  digest: string,
  identity: string,
  onHoldStatus: boolean,
  nonce: number | BigNumber
): Promise<{ typeDataHash: string }> {
  const ONHOLD_TYPEHASH = keccak256(
    toUtf8Bytes(
      "OnHold(bytes32 digest,address identity,bool onHoldStatus,uint64 nonce)"
    )
  );
  // 1. Build struct data hash
  const encodedMessage = defaultAbiCoder.encode(
    ["bytes32", "bytes32", "address", "bool", "uint64"],
    [ONHOLD_TYPEHASH, digest, identity, onHoldStatus, nonce]
  );

  const typeDataHash = await getTypedDataHash(encodedMessage);
  return typeDataHash;
}

async function getTypedDataHashForOnHoldWithCustomTypeOfDelegate_Type(
  digest: string,
  identity: string,
  onHoldStatus: boolean,
  nonce: number | BigNumber,
  delegateType: string
): Promise<{ typeDataHash: string }> {
  const ONHOLD_WITH_CUSTOM_DELEGATE_TYPE_TYPEHASH = keccak256(
    toUtf8Bytes(
      "OnHoldByDelegateWithCustomType(bytes32 digest,address identity,bool onHoldStatus,uint64 nonce,bytes32 delegateType)"
    )
  );
  // 1. Build struct data hash
  const encodedMessage = defaultAbiCoder.encode(
    ["bytes32", "bytes32", "address", "bool", "uint64", "bytes32"],
    [
      ONHOLD_WITH_CUSTOM_DELEGATE_TYPE_TYPEHASH,
      digest,
      identity,
      onHoldStatus,
      nonce,
      delegateType,
    ]
  );

  const typeDataHash = await getTypedDataHash(encodedMessage);
  return typeDataHash;
}

async function getTypedDataHashForRemoveDelegateType(
  delegateType: string,
  nonce: number | BigNumber
): Promise<{ typeDataHash: string }> {
  const REMOVE_DELEGATE_TYPEHASH = keccak256(
    toUtf8Bytes("RemoveDelegateType(bytes32 delegateType,uint64 nonce)")
  );

  // 1. Build struct data hash
  const encodedMessage = defaultAbiCoder.encode(
    ["bytes32", "bytes32", "uint64"],
    [REMOVE_DELEGATE_TYPEHASH, delegateType, nonce]
  );

  const typeDataHash = await getTypedDataHash(encodedMessage);
  return typeDataHash;
}

async function getTypedDataHash(
  encodedMessage: string,
  contractName = EIP712ContractName,
  chainId = network.config.chainId,
  version = contractVersion
): Promise<{ typeDataHash: string }> {
  const structHash = keccak256(arrayify(encodedMessage)); // OK
  const domainSeparator = await getDomainSeparator(
    contractName,
    version,
    chainId
  );
  // 2.2 Build type data hash
  // Inputs: structHash and domainSeparator
  const typeData = ethers.utils.solidityPack(
    ["bytes1", "bytes1", "bytes32", "bytes32"],
    [0x19, 0x01, domainSeparator, structHash]
  );
  const typeDataHash = keccak256(typeData);
  return { typeDataHash };
}

async function getTypedDataHashForRemoveDidRegistry(
  nonce: number | BigNumber,
  contractName = EIP712ContractName,
  chainId = network.config.chainId,
  version = contractVersion
): Promise<{ typeDataHash: string }> {
  const REMOVE_DID_REGISTRY_TYPEHASH = keccak256(
    toUtf8Bytes("RemoveDidRegistry(uint64 nonce)")
  );

  // 0. Build digest
  // const digest = keccak256(toUtf8Bytes(message));

  // 1. Build struct data hash
  const encodedMessage = defaultAbiCoder.encode(
    ["bytes32", "uint64"],
    [REMOVE_DID_REGISTRY_TYPEHASH, nonce]
  );
  const structHash = keccak256(arrayify(encodedMessage)); // OK

  // 2. EIP712
  // 2.1 build domainSeparator
  const TYPE_HASH = keccak256(
    toUtf8Bytes(
      "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    )
  );
  const _hashedName = keccak256(toUtf8Bytes(contractName));
  const _hashedVersion = keccak256(toUtf8Bytes(version));

  const contractAddress = verificationRegistryAddress;
  const eds = defaultAbiCoder.encode(
    ["bytes32", "bytes32", "bytes32", "uint256", "address"],
    [TYPE_HASH, _hashedName, _hashedVersion, chainId, contractAddress]
  );
  const domainSeparator = keccak256(eds); // OK

  // 2.2 Build type data hash
  // Inputs: structHash and domainSeparator
  const typeData = ethers.utils.solidityPack(
    ["bytes1", "bytes1", "bytes32", "bytes32"],
    [0x19, 0x01, domainSeparator, structHash]
  );
  const typeDataHash = keccak256(typeData);
  return { typeDataHash };
}

async function getDomainSeparator(
  contractName: string,
  version = contractVersion,
  chainId = network.config.chainId
): Promise<string> {
  // 1. EIP712
  // 1.1 build domainSeparator
  const TYPE_HASH = keccak256(
    toUtf8Bytes(
      "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    )
  );
  const _hashedName = keccak256(toUtf8Bytes(contractName));
  const _hashedVersion = keccak256(toUtf8Bytes(version));

  const contractAddress = verificationRegistryAddress;
  const eds = defaultAbiCoder.encode(
    ["bytes32", "bytes32", "bytes32", "uint256", "address"],
    [TYPE_HASH, _hashedName, _hashedVersion, chainId, contractAddress]
  );
  const domainSeparator = keccak256(eds);
  return domainSeparator;
}

async function addDidRegistrySigned(
  didRegistryAddress: string,
  organization: Wallet
) {
  const anySender = entity3;
  const Artifact = await ethers.getContractFactory(artifactName, anySender);
  const contractInstance = Artifact.attach(verificationRegistryAddress);
  const didRegistryDetails = await contractInstance.getDidRegistry(
    organization.address
  );
  const oldDidRegistry = (
    await contractInstance.didRegistries(organization.address)
  ).didRegistry;

  let nonce = didRegistryDetails.nonce;
  const { typeDataHash } = await getTypedDataHashForAddDidRegistry(
    didRegistryAddress,
    nonce
  );
  // sign type data hash
  const signingKey = organization._signingKey;
  const { v, r, s } = signingKey().signDigest(typeDataHash);
  // 3. Send Signed Transaction
  const result = await contractInstance.addDidRegistrySigned(
    didRegistryAddress,
    nonce,
    v,
    r,
    s
  );
  await result.wait();
  await expect(result)
    .to.emit(contractInstance, "DidRegistryChange")
    .withArgs(organization.address, oldDidRegistry, didRegistryAddress);
  const updatedNonce = (
    await contractInstance.getDidRegistry(organization.address)
  ).nonce;

  expect(updatedNonce).to.equal(nonce.add(1));

  return { v, r, s, nonce };
}

async function removeDidRegistrySigned(organization: Wallet) {
  const anySender = entity3;
  const Artifact = await ethers.getContractFactory(artifactName, anySender);
  const contractInstance = Artifact.attach(verificationRegistryAddress);
  const initialState = await contractInstance.didRegistries(
    organization.address
  );
  const nonce = initialState.nonce;
  const { typeDataHash } = await getTypedDataHashForRemoveDidRegistry(nonce);
  // sign type data hash
  const signingKey = organization._signingKey;
  const { v, r, s } = signingKey().signDigest(typeDataHash);
  // 3. Send Signed Transaction
  const result = await contractInstance.removeDidRegistrySigned(nonce, v, r, s);
  await result.wait();
  await expect(result)
    .to.emit(contractInstance, "DidRegistryChange")
    .withArgs(
      organization.address,
      initialState.didRegistry,
      ethers.constants.AddressZero
    );
  return { v, r, s, nonce };
}

async function addDelegateTypeSigned(
  customDelegateType: string,
  organization: Wallet
) {
  const anySender = entity3;
  const Artifact = await ethers.getContractFactory(artifactName, anySender);
  const contractInstance = Artifact.attach(verificationRegistryAddress);
  const delegateTypeDetails = await contractInstance.didDelegateTypes(
    organization.address,
    customDelegateType
  );
  const nonce = delegateTypeDetails.nonce;
  const { typeDataHash } = await getTypedDataHashForAddDelegateType(
    customDelegateType,
    nonce
  );
  // sign type data hash
  const signingKey = organization._signingKey;
  const { v, r, s } = signingKey().signDigest(typeDataHash);
  // 3. Send Signed Transaction
  const result = await contractInstance.addDelegateTypeSigned(
    customDelegateType,
    nonce,
    v,
    r,
    s
  );
  await result.wait();

  await expect(result)
    .to.emit(contractInstance, "NewDelegateTypeChange")
    .withArgs(customDelegateType, organization.address, true);
  return { v, r, s, nonce };
}

async function removeDelegateTypeSigned(
  customDelegateType: string,
  organization: Wallet
) {
  const anySender = entity3;
  const Artifact = await ethers.getContractFactory(artifactName, anySender);
  const contractInstance = Artifact.attach(verificationRegistryAddress);
  const delegateTypeDetails = await contractInstance.didDelegateTypes(
    organization.address,
    customDelegateType
  );
  const nonce = delegateTypeDetails.nonce;

  const { typeDataHash } = await getTypedDataHashForRemoveDelegateType(
    customDelegateType,
    nonce
  );
  // sign type data hash
  const signingKey = organization._signingKey;
  const { v, r, s } = signingKey().signDigest(typeDataHash);
  // 3. Send Signed Transaction
  const result = await contractInstance.removeDelegateTypeSigned(
    customDelegateType,
    nonce,
    v,
    r,
    s
  );
  await result.wait();

  await expect(result)
    .to.emit(contractInstance, "NewDelegateTypeChange")
    .withArgs(customDelegateType, organization.address, false);
  return { v, r, s, nonce };
}

async function addOnHoldSigned(
  message = genericMessage,
  organization: Wallet,
  status: boolean,
  nonce: number
) {
  const digest = keccak256(toUtf8Bytes(message));
  const { typeDataHash } = await getTypedDataHashForOnHoldType(
    digest,
    organization.address,
    status,
    nonce
  );
  // sign type data hash
  const signingKey = organization._signingKey;
  const { v, r, s } = signingKey().signDigest(typeDataHash);
  // 3. Send Signed Transaction
  const anySender = entity3;
  const Artifact = await ethers.getContractFactory(artifactName, anySender);
  const contractInstance = Artifact.attach(verificationRegistryAddress);

  const result = await contractInstance.onHoldChangeSigned(
    digest,
    organization.address,
    status,
    nonce,
    v,
    r,
    s
  );
  await result.wait();

  await expect(result)
    .to.emit(contractInstance, "NewOnHoldChange")
    .withArgs(digest, organization.address, status, anyValue);
  const q = await contractInstance.getDetails(organization.address, digest);
  expect(q.onHold).to.equal(status);
  expect(q.nonce).to.equal(nonce + 1);
  return { v, r, s, nonce };
}

async function addOnHoldByDelegateSigned(
  message = genericMessage,
  organizationAddress: string,
  status: boolean,
  delegate: Wallet
) {
  const digest = keccak256(toUtf8Bytes(message));
  const anySender = entity3;
  const Artifact = await ethers.getContractFactory(artifactName, anySender);
  const contractInstance = Artifact.attach(verificationRegistryAddress);
  const digestDetails = await contractInstance.getDetails(
    organizationAddress,
    digest
  );
  const nonce = digestDetails.nonce;
  const { typeDataHash } = await getTypedDataHashForOnHoldType(
    digest,
    organizationAddress,
    status,
    nonce
  );
  // sign type data hash
  const signingKey = delegate._signingKey;
  const { v, r, s } = signingKey().signDigest(typeDataHash);
  // 3. Send Signed Transaction
  const result = await contractInstance.onHoldByDelegateSigned(
    digest,
    organizationAddress,
    status,
    nonce,
    v,
    r,
    s
  );
  await result.wait();

  await expect(result)
    .to.emit(contractInstance, "NewOnHoldChange")
    .withArgs(digest, organizationAddress, status, anyValue);
  const q = await contractInstance.getDetails(organizationAddress, digest);
  expect(q.onHold).to.equal(status);
  expect(q.nonce).to.equal(nonce.add(1));

  return { v, r, s, nonce };
}

async function addOnHoldByDelegateWithCustomTypeSigned(
  customDelegateType: string,
  message = genericMessage,
  organizationAddress: string,
  status: boolean,
  delegate: Wallet
) {
  const anySender = entity3;
  const Artifact = await ethers.getContractFactory(artifactName, anySender);
  const contractInstance = Artifact.attach(verificationRegistryAddress);
  const digest = keccak256(toUtf8Bytes(message));
  const initialState = await contractInstance.getDetails(
    organizationAddress,
    digest
  );
  const { typeDataHash } =
    await getTypedDataHashForOnHoldWithCustomTypeOfDelegate_Type(
      digest,
      organizationAddress,
      status,
      initialState.nonce,
      customDelegateType
    );
  // sign type data hash
  const signingKey = delegate._signingKey;
  const { v, r, s } = signingKey().signDigest(typeDataHash);
  // 3. Send Signed Transaction

  const result = await contractInstance.onHoldByDelegateWithCustomTypeSigned(
    customDelegateType,
    organizationAddress,
    digest,
    status,
    initialState.nonce,
    v,
    r,
    s
  );
  await result.wait();

  await expect(result)
    .to.emit(contractInstance, "NewOnHoldChange")
    .withArgs(digest, organizationAddress, status, anyValue);
  const q = await contractInstance.getDetails(organizationAddress, digest);
  expect(q.onHold).to.equal(status);

  const nonce = initialState.nonce;
  return { v, r, s, nonce };
}
