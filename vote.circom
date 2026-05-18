pragma circom 2.0.0;
include "node_modules/circomlib/circuits/poseidon.circom";

template VoteCheck() {
    signal input vote;
    signal input randomness;
    signal input ciphertextHash;

    vote * (vote - 1) === 0;

    component pos = Poseidon(2);
    pos.inputs[0] <== ciphertextHash;
    pos.inputs[1] <== randomness;

    signal output commitment;
    commitment <== pos.out;
}

component main {public [ciphertextHash]} = VoteCheck();