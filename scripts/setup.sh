#!/usr/bin/env bash
# Compile the Circom circuit and run a dev trusted setup.
# Prerequisites: circom 2.1.6, snarkjs 0.7.6, node 20
#   npm install -g circom snarkjs
#
# Usage: setup.sh [CIRCUIT_NAME]
#   CIRCUIT_NAME defaults to the production circuit. Passing a name lets the evaluation
#   harness build size-variants (circuits/src/<name>.circom) for the ZKP scaling sweep.
# Env:
#   PTAU_POWER  powers-of-tau size (default 14 = up to 2^14 constraints; raise for bigger variants)
#
# For the sweep it also prints machine-parseable lines the bench parses:
#   TIMING compile <ms> · TIMING setup <ms> · CONSTRAINTS <n>

set -euo pipefail

CIRCUIT_NAME="${1:-prescription_validation_poseidon_merkle}"
PTAU_POWER="${PTAU_POWER:-14}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CIRCUIT_SRC="$ROOT/circuits/src/${CIRCUIT_NAME}.circom"
OUT_DIR="$ROOT/circuits"

now_ms() { date +%s%3N; }

echo "==> Compiling circuit ${CIRCUIT_NAME} (ptau 2^${PTAU_POWER})..."
t0=$(now_ms)
circom "$CIRCUIT_SRC" \
  --r1cs --wasm --sym \
  --output "$OUT_DIR" \
  -l node_modules
t1=$(now_ms)
echo "TIMING compile $((t1 - t0))"

# Constraint count (parseable).
CONSTRAINTS="$(snarkjs r1cs info "$OUT_DIR/${CIRCUIT_NAME}.r1cs" 2>/dev/null | grep -iE '# of Constraints' | grep -oE '[0-9]+' | head -1 || echo 0)"
echo "CONSTRAINTS ${CONSTRAINTS}"

echo "==> Trusted setup (dev ceremony)..."
t2=$(now_ms)
snarkjs powersoftau new bn128 "$PTAU_POWER" "$OUT_DIR/pot_0.ptau" -v
snarkjs powersoftau contribute "$OUT_DIR/pot_0.ptau" "$OUT_DIR/pot_1.ptau" --name="dev" -e="random entropy"
snarkjs powersoftau prepare phase2 "$OUT_DIR/pot_1.ptau" "$OUT_DIR/pot_final.ptau" -v

echo "==> Groth16 circuit-specific setup..."
snarkjs groth16 setup "$OUT_DIR/${CIRCUIT_NAME}.r1cs" "$OUT_DIR/pot_final.ptau" "$OUT_DIR/${CIRCUIT_NAME}_0.zkey"
snarkjs zkey contribute "$OUT_DIR/${CIRCUIT_NAME}_0.zkey" "$OUT_DIR/${CIRCUIT_NAME}_final.zkey" --name="dev" -e="random entropy"
snarkjs zkey export verificationkey "$OUT_DIR/${CIRCUIT_NAME}_final.zkey" "$OUT_DIR/${CIRCUIT_NAME}_vkey.json"
t3=$(now_ms)
echo "TIMING setup $((t3 - t2))"

# Move the wasm from the circom output subdirectory.
WASM_SUBDIR="$OUT_DIR/${CIRCUIT_NAME}_js"
if [ -d "$WASM_SUBDIR" ]; then
  cp "$WASM_SUBDIR/${CIRCUIT_NAME}.wasm" "$OUT_DIR/"
fi

# Back-compat: the production build expects circuit_final.zkey / verification_key.json.
if [ "$CIRCUIT_NAME" = "prescription_validation_poseidon_merkle" ]; then
  cp "$OUT_DIR/${CIRCUIT_NAME}_final.zkey" "$OUT_DIR/circuit_final.zkey"
  cp "$OUT_DIR/${CIRCUIT_NAME}_vkey.json" "$OUT_DIR/verification_key.json"
fi

echo "==> Done. Artifacts in $OUT_DIR:"
ls -lh "$OUT_DIR/${CIRCUIT_NAME}.wasm" "$OUT_DIR/${CIRCUIT_NAME}_final.zkey" "$OUT_DIR/${CIRCUIT_NAME}_vkey.json" 2>/dev/null || true
