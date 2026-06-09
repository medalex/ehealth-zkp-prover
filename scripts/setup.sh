#!/usr/bin/env bash
# Compile the Circom circuit and run a dev trusted setup.
# Prerequisites: circom 2.1.6, snarkjs 0.7.6, node 20
#   npm install -g circom snarkjs

set -euo pipefail

CIRCUIT_SRC="$(cd "$(dirname "$0")/.." && pwd)/circuits/src/prescription_validation_poseidon_merkle.circom"
OUT_DIR="$(cd "$(dirname "$0")/.." && pwd)/circuits"

echo "==> Compiling circuit..."
circom "$CIRCUIT_SRC" \
  --r1cs --wasm --sym \
  --output "$OUT_DIR" \
  -l node_modules

echo "==> Trusted setup (dev ceremony)..."
snarkjs powersoftau new bn128 14 "$OUT_DIR/pot14_0.ptau" -v
snarkjs powersoftau contribute "$OUT_DIR/pot14_0.ptau" "$OUT_DIR/pot14_1.ptau" --name="dev" -e="random entropy"
snarkjs powersoftau prepare phase2 "$OUT_DIR/pot14_1.ptau" "$OUT_DIR/pot14_final.ptau" -v

echo "==> Groth16 circuit-specific setup..."
snarkjs groth16 setup "$OUT_DIR/prescription_validation_poseidon_merkle.r1cs" "$OUT_DIR/pot14_final.ptau" "$OUT_DIR/circuit_0.zkey"
snarkjs zkey contribute "$OUT_DIR/circuit_0.zkey" "$OUT_DIR/circuit_final.zkey" --name="dev" -e="random entropy"
snarkjs zkey export verificationkey "$OUT_DIR/circuit_final.zkey" "$OUT_DIR/verification_key.json"

# Move the wasm from the circom output subdirectory
WASM_SUBDIR="$OUT_DIR/prescription_validation_poseidon_merkle_js"
if [ -d "$WASM_SUBDIR" ]; then
  cp "$WASM_SUBDIR/prescription_validation_poseidon_merkle.wasm" "$OUT_DIR/"
fi

echo "==> Done. Artifacts in $OUT_DIR:"
ls -lh "$OUT_DIR"/*.wasm "$OUT_DIR"/*.zkey "$OUT_DIR/verification_key.json"
