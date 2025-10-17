import { ethers } from "hardhat";
import { formatBytes32String } from "ethers/lib/utils";

async function main() {
  const [deployer] = await ethers.getSigners();
  const artifactName = "VerificationRegistry";
  const defaultDidRegistry = "0xEFD4cadFD62DF1FC003C6edEA2CE3a55cc4565A9"; // UPDATE this!
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
