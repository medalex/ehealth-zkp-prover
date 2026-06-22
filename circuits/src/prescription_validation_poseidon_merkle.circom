pragma circom 2.1.6;

include "circomlib/circuits/poseidon.circom";

template ForceBool() {
    signal input in;
    in * (in - 1) === 0;
}

template Num2Bits(n) {
    signal input in;
    signal output out[n];

    var lc = 0;
    var e2 = 1;
    for (var i = 0; i < n; i++) {
        out[i] <-- (in >> i) & 1;
        out[i] * (out[i] - 1) === 0;
        lc += out[i] * e2;
        e2 = e2 + e2;
    }
    lc === in;
}

template IsZero() {
    signal input in;
    signal output out;
    signal inv;

    inv <-- in != 0 ? 1 / in : 0;
    out <== 1 - in * inv;
    in * out === 0;
}

template IsEqual() {
    signal input a;
    signal input b;
    signal output out;

    component iz = IsZero();
    iz.in <== a - b;
    out <== iz.out;
}

template LessThan(n) {
    signal input a;
    signal input b;
    signal output out;

    component n2b = Num2Bits(n + 1);
    n2b.in <== a + (1 << n) - b;
    out <== 1 - n2b.out[n];
}

template LessEqThan(n) {
    signal input a;
    signal input b;
    signal output out;

    component lt = LessThan(n);
    lt.a <== a;
    lt.b <== b + 1;
    out <== lt.out;
}

template PoseidonHash2() {
    signal input left;
    signal input right;
    signal output out;

    component h = Poseidon(2);
    h.inputs[0] <== left;
    h.inputs[1] <== right;
    out <== h.out;
}

template AndN(n) {
    signal input in[n];
    signal output out;

    signal acc[n + 1];
    acc[0] <== 1;
    for (var i = 0; i < n; i++) {
        acc[i + 1] <== acc[i] * in[i];
    }
    out <== acc[n];
}

template SelectValue(n) {
    signal input key;
    signal input keys[n];
    signal input values[n];
    signal output selected;

    component eq[n];
    signal match[n];
    signal matchAcc[n + 1];
    signal selAcc[n + 1];

    matchAcc[0] <== 0;
    selAcc[0] <== 0;

    for (var i = 0; i < n; i++) {
        eq[i] = IsEqual();
        eq[i].a <== key;
        eq[i].b <== keys[i];
        match[i] <== eq[i].out;

        matchAcc[i + 1] <== matchAcc[i] + match[i];
        selAcc[i + 1] <== selAcc[i] + match[i] * values[i];
    }

    matchAcc[n] === 1;
    selected <== selAcc[n];
}

template PoseidonMerkleProof(depth) {
    signal input leaf;
    signal input expectedRoot;
    signal input siblings[depth];
    signal input pathBits[depth];
    signal output valid;
    signal output computedRoot;

    signal cur[depth + 1];
    component pathBool[depth];
    component h[depth];
    component eq;

    cur[0] <== leaf;

    for (var i = 0; i < depth; i++) {
        pathBool[i] = ForceBool();
        pathBool[i].in <== pathBits[i];

        h[i] = PoseidonHash2();
        h[i].left <== cur[i] + pathBits[i] * (siblings[i] - cur[i]);
        h[i].right <== siblings[i] + pathBits[i] * (cur[i] - siblings[i]);
        cur[i + 1] <== h[i].out;
    }

    computedRoot <== cur[depth];

    eq = IsEqual();
    eq.a <== computedRoot;
    eq.b <== expectedRoot;
    valid <== eq.out;
}

// Main template.
// N_DRUGS      — number of approved drugs.
// N_max        — max number of patient record reference slots, each with its own
//                Merkle proof against root_M.
//                Circuit size: n_total ≈ n_cred + N_max·n_Merkle + |Pol|·n_range.
// N_PRESC      — number of prescriptions per proof.
// BITLEN       — bit width for range checks.
// MERKLE_DEPTH — Merkle tree depth.
template PrescriptionValidation(N_DRUGS, N_max, N_PRESC, BITLEN, MERKLE_DEPTH) {

    // ── Private inputs ──────────────────────────────────────────────────────────

    // Physician credential
    signal input doctorCredentialHash;
    signal input credentialSiblings[MERKLE_DEPTH];
    signal input credentialPathBits[MERKLE_DEPTH];

    // Prescription data
    signal input prescribedDrugIds[N_PRESC];
    signal input prescribedDosages[N_PRESC];
    signal input childMaxDosages[N_DRUGS];

    signal input patientAge;
    signal input prescriptionTimestamp;
    signal input validFor;
    signal input currentTimestamp;
    signal input workflowId;

    // N_max patient record reference slots (allergies etc.)
    // refLeaf[i]     = Poseidon(recordId, recordType, substanceId, ...)
    // refIsActive[i] = 1 for an active slot, 0 for padding
    // Inactive slots pass all checks tautologically.
    signal input refLeaf[N_max];
    signal input refSiblings[N_max][MERKLE_DEPTH];
    signal input refPathBits[N_max][MERKLE_DEPTH];
    signal input refIsActive[N_max];

    // ── Public inputs ───────────────────────────────────────────────────────────

    // validCredentialRoot — physician registry root (MFSSIA → DKG, external, pre-committed)
    signal input validCredentialRoot;
    // patientRecordRoot — patient record root (allergies, built locally by the prover)
    signal input patientRecordRoot;
    signal input nonce;
    signal input policyDrugIds[N_DRUGS];
    signal input adultMaxDosages[N_DRUGS];
    // allergyMatrix[i][j] = 1 if allergen from slot i contraindicates drug j
    signal input allergyMatrix[N_max][N_DRUGS];

    // ── Outputs ─────────────────────────────────────────────────────────────────
    signal output outcome;
    signal output stmtHash;

    // ── Policy 1: CredValid — physician in registry ─────────────────────────────
    signal policy1;

    component credProof = PoseidonMerkleProof(MERKLE_DEPTH);
    credProof.leaf       <== doctorCredentialHash;
    credProof.expectedRoot <== validCredentialRoot;
    for (var d = 0; d < MERKLE_DEPTH; d++) {
        credProof.siblings[d]  <== credentialSiblings[d];
        credProof.pathBits[d]  <== credentialPathBits[d];
    }
    policy1 <== credProof.valid;

    // ── Merkle proofs for N_max reference slots ─────────────────────────────────
    // An active slot (refIsActive=1) must have a valid proof against root_M.
    // An inactive slot (refIsActive=0) — no proof constraint.
    component refProof[N_max];
    component refActiveBool[N_max];
    component allergyBool[N_max][N_DRUGS];
    signal activeAndValid[N_max];

    for (var i = 0; i < N_max; i++) {
        refActiveBool[i] = ForceBool();
        refActiveBool[i].in <== refIsActive[i];

        refProof[i] = PoseidonMerkleProof(MERKLE_DEPTH);
        refProof[i].leaf         <== refLeaf[i];
        refProof[i].expectedRoot <== patientRecordRoot;
        for (var d = 0; d < MERKLE_DEPTH; d++) {
            refProof[i].siblings[d] <== refSiblings[i][d];
            refProof[i].pathBits[d] <== refPathBits[i][d];
        }

        // refIsActive[i] === refIsActive[i] * refProof[i].valid
        // ⟹ when refIsActive=1 we require valid=1; when refIsActive=0 — no constraint.
        activeAndValid[i] <== refIsActive[i] * refProof[i].valid;
        refIsActive[i] === activeAndValid[i];

        for (var j = 0; j < N_DRUGS; j++) {
            allergyBool[i][j] = ForceBool();
            allergyBool[i][j].in <== allergyMatrix[i][j];
        }
    }

    // ── Policy 2: NoContraindication — no allergy to prescribed drug ────────────
    signal policy2;
    component rowSel[N_PRESC][N_max];
    signal activeAllergyConflict[N_PRESC][N_max];
    signal noConflictRow[N_PRESC][N_max];
    signal noAllergyPerRx[N_PRESC];
    component allNoConflict[N_PRESC];

    // ── Policy 3: DosageOk — dosage within permitted limits ─────────────────────
    signal policy3;
    component childSel[N_PRESC];
    component adultSel[N_PRESC];
    component leChild[N_PRESC];
    component leAdult[N_PRESC];
    signal dosageOkPerRx[N_PRESC];

    component ageIsChild = LessThan(BITLEN);
    ageIsChild.a <== patientAge;
    ageIsChild.b <== 11;

    for (var p = 0; p < N_PRESC; p++) {
        childSel[p] = SelectValue(N_DRUGS);
        childSel[p].key <== prescribedDrugIds[p];

        adultSel[p] = SelectValue(N_DRUGS);
        adultSel[p].key <== prescribedDrugIds[p];

        for (var i1 = 0; i1 < N_DRUGS; i1++) {
            childSel[p].keys[i1]   <== policyDrugIds[i1];
            childSel[p].values[i1] <== childMaxDosages[i1];
            adultSel[p].keys[i1]   <== policyDrugIds[i1];
            adultSel[p].values[i1] <== adultMaxDosages[i1];
        }

        for (var i2 = 0; i2 < N_max; i2++) {
            rowSel[p][i2] = SelectValue(N_DRUGS);
            rowSel[p][i2].key <== prescribedDrugIds[p];
            for (var j2 = 0; j2 < N_DRUGS; j2++) {
                rowSel[p][i2].keys[j2]   <== policyDrugIds[j2];
                rowSel[p][i2].values[j2] <== allergyMatrix[i2][j2];
            }
            // Active slot: allergy record is applied.
            // Inactive slot (padding): no conflict tautologically.
            activeAllergyConflict[p][i2] <== refIsActive[i2] * rowSel[p][i2].selected;
            noConflictRow[p][i2] <== 1 - activeAllergyConflict[p][i2];
        }

        allNoConflict[p] = AndN(N_max);
        for (var i3 = 0; i3 < N_max; i3++) {
            allNoConflict[p].in[i3] <== noConflictRow[p][i3];
        }
        noAllergyPerRx[p] <== allNoConflict[p].out;

        leChild[p] = LessEqThan(BITLEN);
        leAdult[p] = LessEqThan(BITLEN);

        leChild[p].a <== prescribedDosages[p];
        leChild[p].b <== childSel[p].selected;

        leAdult[p].a <== prescribedDosages[p];
        leAdult[p].b <== adultSel[p].selected;

        dosageOkPerRx[p] <== leAdult[p].out + ageIsChild.out * (leChild[p].out - leAdult[p].out);
    }

    component allP2 = AndN(N_PRESC);
    component allP3 = AndN(N_PRESC);
    for (var p2 = 0; p2 < N_PRESC; p2++) {
        allP2.in[p2] <== noAllergyPerRx[p2];
        allP3.in[p2] <== dosageOkPerRx[p2];
    }
    policy2 <== allP2.out;
    policy3 <== allP3.out;

    // ── Policy 4: TimeValid — prescription is still valid ───────────────────────
    signal policy4;
    component timeLe = LessEqThan(BITLEN);
    timeLe.a <== currentTimestamp;
    timeLe.b <== prescriptionTimestamp + validFor;
    policy4 <== timeLe.out;

    // ── Policy 5: NonceBind — nonce is bound to workflowId ──────────────────────
    signal policy5;
    component wfHash = Poseidon(1);
    wfHash.inputs[0] <== workflowId;

    component nonceEq = IsEqual();
    nonceEq.a <== wfHash.out;
    nonceEq.b <== nonce;
    policy5 <== nonceEq.out;

    // ── Final AND(P1..P5) ────────────────────────────────────────────────────────
    component finalAnd = AndN(5);
    finalAnd.in[0] <== policy1;
    finalAnd.in[1] <== policy2;
    finalAnd.in[2] <== policy3;
    finalAnd.in[3] <== policy4;
    finalAnd.in[4] <== policy5;
    outcome <== finalAnd.out;

    // ── stmtHash = Poseidon(dCH, nonce, drugIds..., dosages...) ─────────────────
    component stmtHasher = Poseidon(2 * N_PRESC + 2);
    stmtHasher.inputs[0] <== doctorCredentialHash;
    stmtHasher.inputs[1] <== nonce;
    for (var k = 0; k < N_PRESC; k++) {
        stmtHasher.inputs[2 + k]           <== prescribedDrugIds[k];
        stmtHasher.inputs[2 + N_PRESC + k] <== prescribedDosages[k];
    }
    stmtHash <== stmtHasher.out;
}

// Public inputs: the verifier binds a proof to:
//   - physician registry root (validCredentialRoot from DKG via MFSSIA)
//   - patient record root    (patientRecordRoot — allergies, built locally)
//   - policy parameters T   (policyDrugIds, adultMaxDosages)
//   - specific prescription  (stmtHash, nonce)
// stmtHash and outcome are circuit outputs and are always public.
// allergyMatrix is a PRIVATE input — the verifier sees only the outcome, not patient allergy data.
// Total public signals: 2 outputs + 10 public inputs = 12.
component main {public [
    doctorCredentialHash,
    validCredentialRoot,
    patientRecordRoot,
    nonce,
    policyDrugIds,
    adultMaxDosages
]} = PrescriptionValidation(3, 3, 1, 32, 3);
