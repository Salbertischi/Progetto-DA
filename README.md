# Palestine National Identity System - ZK Stack Implementation

## Project Overview
This repository contains the smart contract layer for the Palestine National Identity System. The system provides a sovereign, privacy-preserving digital identity solution utilizing Zero-Knowledge Proofs (ZKPs). It enables citizens to prove eligibility for services (e.g., age verification, citizenship) without revealing underlying sensitive personal data.

## Architecture Overview

The system is built on a modular, upgradeable smart contract architecture, strictly separating the core identity state from the verification logic.

### CoreIdentityCredential.sol
This contract acts as the foundational anchor for the identity system. It manages the lifecycle of digital credentials.
* **Issuance:** Authorized entities (`ISSUER_ROLE`) can issue credentials securely anchored on-chain via a cryptographic hash.
* **Revocation Registry:** Supports both individual credential revocation and gas-efficient batch revocations using a Merkle Tree approach (storing only the Merkle Root on-chain).
* **Emergency Controls:** Implements the `Pausable` pattern to halt issuance and revocation in case of a critical breach.

### ZKPVerification.sol
This contract serves as the privacy layer and the main entry point for external Service Providers (e.g., hospitals, banks).
* **Selective Disclosure:** Facilitates the `requestDisclosure` flow, allowing providers to verify specific claims without accessing the citizen's full identity data.
* **Zero-Knowledge Integration:** Interfaces with SnarkJS-generated verifiers (e.g., `AgeVerifier`) to validate mathematical proofs submitted by citizens.
* **Scope-Based Access Control (RBAC):** Uses a granular permission system (`AGE_PROVIDER_ROLE`, `CITIZENSHIP_PROVIDER_ROLE`, etc.) to ensure that Service Providers can only request information they are legally authorized to access.
* **Audit Trail:** Emits `DisclosureRecorded` events for every successful verification to ensure complete transparency.

## System Flow
1. **Issuance:** The government issues a credential to the citizen. The `CoreIdentityCredential` stores the hash and the expiration timestamp.
2. **Proof Generation (Off-chain):** The citizen's device generates a zk-SNARK proof demonstrating a specific claim (e.g., "Age > 18") and that the credential is valid and not revoked.
3. **Verification (On-chain):** A Service Provider submits the proof to `ZKPVerification`. The contract checks the provider's scope, validates the ZKP, ensures the credential is still active in the Core contract, and logs the event.

## Security Features
* **Upgradeable Proxies:** Both contracts are deployed behind ERC1967 Proxies, allowing future logic upgrades without losing state.
* **Pausable System:** Independent emergency pause mechanisms for both the issuance core and the verification layer.
* **Replay Attack Protection:** ZKPs are cryptographically bound to the specific credential ID.