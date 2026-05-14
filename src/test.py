import json
import shutil
import subprocess
import os

vote = 1

# 1. input
with open("input.json", "w") as f:
    json.dump({"vote": vote}, f)

# 2. compile circom (jeśli nie zrobiłeś ręcznie)
subprocess.run([
    "./circom/target/release/circom.exe", "vote.circom",
    "--r1cs", "--wasm", "--sym", "-l node_modules"
], check=True)

# # 3. witness
subprocess.run([
    "node",
    "vote_js/generate_witness.js",
    "vote_js/vote.wasm",
    "input.json",
    "witness.wtns"
], check=True)

# # 4. PTAU (phase 1)
subprocess.run([
    "cmd", "/c", "snarkjs", "powersoftau", "new",
    "bn128", "12", "pot12_0000.ptau", "-v"
], check=True)

subprocess.run([
    "cmd", "/c", "snarkjs", "powersoftau", "contribute",
    "pot12_0000.ptau",
    "pot12_0001.ptau",
    "-v"
], check=True)

# # PHASE 2 (TO JEST KLUCZ)
subprocess.run([
    "cmd", "/c", "snarkjs", "powersoftau", "prepare", "phase2",
    "pot12_0001.ptau",
    "pot12_final.ptau"
], check=True)

# # ZKEY SETUP (BRAK TEGO U CIEBIE!)
subprocess.run([
    "cmd", "/c", "snarkjs", "groth16", "setup",
    "vote.r1cs",
    "pot12_final.ptau",
    "vote_0.zkey"
], check=True)

# # ZKEY CONTRIBUTION (TYLKO RAZ)
subprocess.run([
    "cmd", "/c", "snarkjs", "zkey", "contribute",
    "vote_0.zkey",
    "vote_final.zkey",
    "-v"
], check=True)


# # 5. generate proof
subprocess.run([
    "cmd", "/c", "snarkjs", "groth16", "prove",
    "vote_final.zkey",
    "witness.wtns",
    "proof.json",
    "public.json"
], check=True)

# # 6. export verification key (jeśli brak)
subprocess.run([
    "cmd", "/c", "snarkjs", "zkey", "export", "verificationkey",
    "vote_final.zkey",
    "verification_key.json"
], check=True)

# # 7. verify
res = subprocess.run([
    "cmd", "/c", "snarkjs", "groth16", "verify",
    "verification_key.json",
    "public.json",
    "proof.json"
], capture_output=True, text=True)

print("Verification result:", res.stdout)