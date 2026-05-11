pragma circom 2.0.0;
include "node_modules/circomlib/circuits/poseidon.circom";

template VoteCheck() {
    signal input vote;           // Prywatne
    signal input randomness;     // Prywatne (sól ZK)
    signal input ciphertextHash; // PUBLICZNE (to jest "kotwica")

    // 1. Sprawdzenie binarności
    vote * (vote - 1) === 0;

    // 2. Wiążemy dowód z hashem szyfrogramu
    // Nawet jeśli nie liczymy Pailliera w środku, ten dowód
    // jest ważny TYLKO dla tego konkretnego hasha.
    component pos = Poseidon(2);
    pos.inputs[0] <== ciphertextHash;
    pos.inputs[1] <== randomness;

    // To wypluje commitment, który serwer sprawdzi
    signal output commitment;
    commitment <== pos.out;
}

component main {public [ciphertextHash]} = VoteCheck();