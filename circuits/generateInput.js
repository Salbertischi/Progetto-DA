// Utility script to generate coherent zkproof suitable for testing

const circomlibjs = require("circomlibjs");
const fs = require("fs");

async function generate() {
    const poseidon = await circomlibjs.buildPoseidon();
    const F = poseidon.F;

    const leaf = 123456789n;
    
    // Nullifier 
    const nullifierHash = poseidon([leaf]);
    const nullifier = F.toString(nullifierHash);

    // Merkle Root 
    let current = leaf;
    const path_elements = [];
    const path_indices = [];
    
    for (let i = 0; i < 20; i++) {
        path_elements.push("0");
        path_indices.push("0"); 
        current = poseidon([current, 0n]);
    }
    
    const root = F.toString(current);

    const input = {
        "citizenAddress": "123456789",
        "citizenSecretHigh": "123",
        "citizenSecretLow": "456",
        "birthTimestamp": "1199145600",
        "currentTimestamp": "1767268800", 
        "leaf": leaf.toString(),
        "path_elements": path_elements,
        "path_indices": path_indices,
        "root": root,
        "nullifier": nullifier
    };

    fs.writeFileSync("input.json", JSON.stringify(input, null, 2));
    console.log("input.json generato con successo!");
}

generate();