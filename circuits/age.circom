pragma circom 2.1.6;

include "node_modules/circomlib/circuits/comparators.circom";
include "node_modules/circomlib/circuits/bitify.circom";
include "node_modules/circomlib/circuits/poseidon.circom";
include "node_modules/circomlib/circuits/mux1.circom";
include "node_modules/keccak-circom/circuits/keccak.circom";


// Component to validate Merkle Tree Path (using Poseidon)
template MerklePath(levels) {
    signal input leaf;
    signal input path_elements[levels];
    signal input path_indices[levels];
    signal output root;

    component hashers[levels];
    component mux[levels][2];

    signal current[levels + 1];
    current[0] <== leaf;

    for (var i = 0; i < levels; i++) {
        hashers[i] = Poseidon(2);
        mux[i][0] = Mux1();
        mux[i][1] = Mux1();

        mux[i][0].c[0] <== current[i];
        mux[i][0].c[1] <== path_elements[i];
        mux[i][0].s <== path_indices[i];

        mux[i][1].c[0] <== path_elements[i];
        mux[i][1].c[1] <== current[i];
        mux[i][1].s <== path_indices[i];

        hashers[i].inputs[0] <== mux[i][0].out;
        hashers[i].inputs[1] <== mux[i][1].out;

        current[i + 1] <== hashers[i].out;
    }

    root <== current[levels];
}

template AgeVerification(levels) {
    // Private input for identity and boundness
    signal input citizenAddress;
    signal input citizenSecretHigh;
    signal input citizenSecretLow;

    // Private input for age
    signal input birthTimestamp;

    // Private input for Merkle Tree
    signal input leaf;                     
    signal input path_elements[levels];    
    signal input path_indices[levels];     

    // Public input (to check on-chain)
    signal input currentTimestamp;
    signal input root;                     
    signal input nullifier;                

    // Output, citizen's hash (divided into two parts)
    signal output citizenHashHigh;
    signal output citizenHashLow;

    // Age validation 
    var EIGHTEEN_YEARS_IN_SECONDS = 567648000;
    component isMaggiorenne = GreaterEqThan(32);
    isMaggiorenne.in[0] <== currentTimestamp;
    isMaggiorenne.in[1] <== birthTimestamp + EIGHTEEN_YEARS_IN_SECONDS;
    isMaggiorenne.out === 1;

    // Identity boundness (using kekkak256)
    component addrBits = Num2Bits(160);
    addrBits.in <== citizenAddress;

    component secretHighBits = Num2Bits(128);
    secretHighBits.in <== citizenSecretHigh;

    component secretLowBits = Num2Bits(128);
    secretLowBits.in <== citizenSecretLow;

    component hasher = Keccak(416, 256);

    for (var i = 0; i < 160; i++) {
        hasher.in[i] <== addrBits.out[159 - i];
    }
    for (var i = 0; i < 128; i++) {
        hasher.in[160 + i] <== secretHighBits.out[127 - i];
    }
    for (var i = 0; i < 128; i++) {
        hasher.in[288 + i] <== secretLowBits.out[127 - i];
    }

    component hashHigh = Bits2Num(128);
    component hashLow = Bits2Num(128);

    for (var i = 0; i < 128; i++) {
        hashHigh.in[i] <== hasher.out[127 - i];
        hashLow.in[i] <== hasher.out[255 - i];
    }

    citizenHashHigh <== hashHigh.out;
    citizenHashLow <== hashLow.out;

    // Verify that the leaf corrisponds to the nullifier (using Poseidon)
    component leaf_hasher = Poseidon(1);
    leaf_hasher.inputs[0] <== leaf;
    nullifier === leaf_hasher.out;

    // Root construction and validation against public root
    component merkle_path = MerklePath(levels);
    merkle_path.leaf <== leaf;
    for (var i = 0; i < levels; i++) {
        merkle_path.path_elements[i] <== path_elements[i];
        merkle_path.path_indices[i] <== path_indices[i];
    }
    root === merkle_path.root;
}

// Tree set with 20 levels (1M credentials)
component main {public [currentTimestamp, root, nullifier]} = AgeVerification(20);