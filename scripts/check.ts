import { ethers } from "hardhat";

async function main() {
  const [deployer] = await ethers.getSigners();
  const Artifact = await ethers.getContractFactory(
    "VerificationRegistry",
    deployer
  );
  const instance = Artifact.attach(
    "0x664D6EbAbbD5cf656eD07A509AFfBC81f9615741"
  );
  const r = await instance.getDetails(
    "0x571115318e2eb2e5d26ba907815bb3a359dffd2a",
    "0xc862148a46985d2e10042eb78e0be2de489b39096f92743c3d62946863c90b82"
    // "0x0e3abbd3a7248508f17d4523a2ab4898f070dcec88066067ea548f1f714f6ff2"
  );
  console.log("details", r);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
