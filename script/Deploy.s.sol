// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "../src/CoreIdentityCredential.sol";
import "../src/RevocationRegistry.sol";
import "../src/ZKPVerification.sol";
import "../src/AgeVerifier.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract DeploySystem is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(deployerPrivateKey);

        // Core Identity
        CoreIdentityCredential coreImpl = new CoreIdentityCredential();
        ERC1967Proxy coreProxy = new ERC1967Proxy(
            address(coreImpl),
            abi.encodeWithSelector(CoreIdentityCredential.initialize.selector)
        );
        CoreIdentityCredential core = CoreIdentityCredential(address(coreProxy));

        // Revocation Registry
        RevocationRegistry registryImpl = new RevocationRegistry();
        ERC1967Proxy registryProxy = new ERC1967Proxy(
            address(registryImpl),
            abi.encodeWithSelector(RevocationRegistry.initialize.selector)
        );
        RevocationRegistry registry = RevocationRegistry(address(registryProxy));

        // ZKP Verification
        ZKPVerification zkpImpl = new ZKPVerification();
        ERC1967Proxy zkpProxy = new ERC1967Proxy(
            address(zkpImpl),
            abi.encodeWithSelector(
                ZKPVerification.initialize.selector, 
                address(core), 
                address(registry)
            )
        );
        ZKPVerification zkp = ZKPVerification(address(zkpProxy));
        
        // Auto-generated (by SnarkJS) verifier
        AgeGroth16Verifier ageVerifier = new AgeGroth16Verifier();
        zkp.setVerifier(ICoreIdentityCredential.CredentialType.AgeVerification, address(ageVerifier));

        // Not implemented
        // Assign the roles to the authorized entities

        vm.stopBroadcast();
    }
}