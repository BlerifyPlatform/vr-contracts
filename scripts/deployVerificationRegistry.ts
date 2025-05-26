import { ethers } from "hardhat";
import { formatBytes32String } from "ethers/lib/utils";

async function main() {
  const [deployer] = await ethers.getSigners();
  const artifactName = "VerificationRegistry";
  const defaultDidRegistry = "0xfeae27388A65eE984F452f86efFEd42AaBD438FD"; // UPDATE this!
  const defaultDelegateType = formatBytes32String("sigAuth"); // bytes32 right padded
  const Artifact = await ethers.getContractFactory(artifactName, deployer);
  const instance = await Artifact.deploy(
    defaultDidRegistry,
    defaultDelegateType
  );
  console.log(
    `${artifactName} instance successfully deployed at address: ` +
      instance.address
  );
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
