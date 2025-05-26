import { ethers, lacchain } from "hardhat";
import { formatBytes32String } from "ethers/lib/utils";

async function main() {
  const accounts = lacchain.getSigners();
  const artifactName = "VerificationRegistryGM";
  const defaultDidRegistry = "0xa4e11c345A2393669b792cb527b8527dbaa73D50"; // UPDATE this!
  const defaultDelegateType = formatBytes32String("sigAuth"); // bytes32 right padded
  console.log(defaultDelegateType);
  const Artifact = await ethers.getContractFactory(artifactName, accounts[0]);
  console.log("Using Base Relay Address:", lacchain.baseRelayAddress);
  const instance = await lacchain.deployContract(
    Artifact,
    lacchain.baseRelayAddress,
    defaultDidRegistry,
    defaultDelegateType
  );
  console.log(
    `${artifactName} instance successfully deployed at address: ` +
      instance.address
  );
  // const contract = Artifact.attach(instance.address);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
