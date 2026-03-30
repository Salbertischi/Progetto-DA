# Palestine National Identity System - ZK Stack Implementation

## Project Overview
This repository contains the smart contract layer for the Palestine National Identity System. The system provides a sovereign, privacy-preserving digital identity solution utilizing Zero-Knowledge Proofs (ZKPs). It enables citizens to prove eligibility for services (e.g., age verification, citizenship) without revealing underlying sensitive personal data.

## Tech Stack
* **Smart Contracts:** Solidity
* **Development Framework:** Foundry
* **Zero-Knowledge Circuits:** Circom
* **Cryptographic Prover/Verifier:** SnarkJS (Groth16)

## Architecture Overview

The system is built on a modular, upgradeable smart contract architecture, strictly separating the core identity state, revocation logic, and verification logic.

### CoreIdentityCredential.sol
This contract acts as the foundational anchor for the identity system. It manages the lifecycle of digital credentials.
* **Issuance:** Authorized entities (`ISSUER_ROLE`) can issue credentials securely anchored on-chain via a cryptographic hash.
* **Emergency Controls:** Implements the `Pausable` pattern to halt issuance in case of a critical breach without locking the verification of existing credentials.

### RevocationRegistry.sol
This dedicated registry handles all privacy-preserving credential revocations.
* **Batch Revocations:** Uses a Merkle Tree approach (storing only the non-revocation Merkle Root on-chain) for highly gas-efficient mass revocations.
* **Immediate Revocations:** Uses ZK-generated nullifiers to instantly blacklist compromised credentials without exposing the citizen's identity or allowing linkability.

### ZKPVerification.sol
This contract serves as the privacy layer and the main entry point for external Service Providers (e.g., hospitals, banks).
* **Selective Disclosure:** Facilitates the `requestDisclosure` flow, allowing providers to verify specific claims without accessing the citizen's full identity data.
* **Zero-Knowledge Integration:** Interfaces with SnarkJS-generated verifiers (e.g., `AgeVerifier`) to validate mathematical proofs submitted by citizens.
* **Scope-Based Access Control (RBAC):** Uses a granular permission system (`AGE_PROVIDER_ROLE`, `CITIZENSHIP_PROVIDER_ROLE`, etc.) to ensure that Service Providers can only request information they are legally authorized to access.
* **Audit Trail:** Emits `DisclosureRecorded` events for every successful verification to ensure complete transparency.

## System Flow
1. **Issuance:** The government issues a credential to the citizen. The `CoreIdentityCredential` stores the hash and the active status.
2. **Proof Generation (Off-chain):** The citizen's device generates a zk-SNARK proof demonstrating a specific claim (e.g., "Age >= 18") and that the credential is valid.
3. **Verification (On-chain):** A Service Provider submits the proof to `ZKPVerification`. The contract checks the provider's scope, executes fail-fast checks against the `CoreIdentityCredential` and `RevocationRegistry`, validates the ZK math, and logs the event.

## Security Features
* **Upgradeable Proxies:** All core contracts are deployed behind ERC1967 Proxies, allowing future logic upgrades without losing state.
* **Compartmentalized Pausable System:** Independent emergency pause mechanisms for the issuance core, the revocation registry, and the verification layer to prevent domino-effect failures.
* **Replay Attack Protection:** ZKPs are cryptographically bound to the specific credential ID and protected by strict temporal validation.

## Quick Start
To run this project locally, ensure you have [Foundry](https://book.getfoundry.sh/) installed.

```bash
# Clone the repository
git clone https://github.com/Salbertischi/Progetto-DA.git
cd Progetto-DA

# Install dependencies
forge install

# Build the smart contracts
forge build

# Run the full test suite
forge test
``` 

## Comprehensive Documentation, Testing & Deployment
For a deep dive into the system's architectural trade-offs, cryptographic design choices, testing and gas optimization strategies and deployment procedure, please refer to the **[Technical Report.pdf](./Technical_Report.pdf)** included in this repository. 
