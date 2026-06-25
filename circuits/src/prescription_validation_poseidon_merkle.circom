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
// N_LAB        — max number of lab-based clinical policy slots (eGFR etc.).
template PrescriptionValidation(N_DRUGS, N_max, N_PRESC, BITLEN, MERKLE_DEPTH, N_LAB) {

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

    // Lab-based clinical policies (eGFR etc.)
    // labValue[L]    — actual patient measurement from lab-api (PRIVATE, trusted prover)
    // labIsActive[L] — 1 = slot in use, 0 = padding (passes tautologically)
    signal input labValue[N_LAB];
    signal input labIsActive[N_LAB];

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

    // Lab policy parameters from DKG (governance-approved, PUBLIC)
    // labThreshold[L]     — clinical threshold value (e.g. 30 for eGFR)
    // labRequiredOp[L]    — required (safe) condition: 0=GTE, 1=LTE, 2=EQ, 3=NEQ
    // labAppliesToDrug[L] — drugId the policy targets (0 for padding slots)
    signal input labThreshold[N_LAB];
    signal input labRequiredOp[N_LAB];
    signal input labAppliesToDrug[N_LAB];

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

    // ── Policy 6: LabPolicyOk — lab-based clinical contraindications ─────────────
    // For each active slot whose policy targets the prescribed drug, the required
    // (safe) condition must hold; otherwise the prescription is blocked.
    // labRequiredOp encodes the SAFE condition; violation = its negation:
    //   GTE(0): safe = value >= threshold → viol = value <  threshold
    //   LTE(1): safe = value <= threshold → viol = threshold < value
    //   EQ (2): safe = value == threshold → viol = value != threshold
    //   NEQ(3): safe = value != threshold → viol = value == threshold
    signal policy6;
    component labActiveBool[N_LAB];
    component labLt[N_LAB];
    component labGt[N_LAB];
    component labEq[N_LAB];
    component isOp0[N_LAB];
    component isOp1[N_LAB];
    component isOp2[N_LAB];
    component isOp3[N_LAB];
    component labApplies[N_LAB];
    signal vlt[N_LAB];
    signal vgt[N_LAB];
    signal veq2[N_LAB];
    signal veq3[N_LAB];
    signal labViol[N_LAB];
    signal labT1[N_LAB];
    signal labBlock[N_LAB];
    signal labNoBlock[N_LAB];
    component allLabOk = AndN(N_LAB);

    for (var L = 0; L < N_LAB; L++) {
        labActiveBool[L] = ForceBool();
        labActiveBool[L].in <== labIsActive[L];

        // value < threshold
        labLt[L] = LessThan(BITLEN);
        labLt[L].a <== labValue[L];
        labLt[L].b <== labThreshold[L];
        // threshold < value
        labGt[L] = LessThan(BITLEN);
        labGt[L].a <== labThreshold[L];
        labGt[L].b <== labValue[L];
        // value == threshold
        labEq[L] = IsEqual();
        labEq[L].a <== labValue[L];
        labEq[L].b <== labThreshold[L];

        // operator selector: exactly one of op∈{0,1,2,3}
        isOp0[L] = IsEqual();  isOp0[L].a <== labRequiredOp[L];  isOp0[L].b <== 0;
        isOp1[L] = IsEqual();  isOp1[L].a <== labRequiredOp[L];  isOp1[L].b <== 1;
        isOp2[L] = IsEqual();  isOp2[L].a <== labRequiredOp[L];  isOp2[L].b <== 2;
        isOp3[L] = IsEqual();  isOp3[L].a <== labRequiredOp[L];  isOp3[L].b <== 3;
        isOp0[L].out + isOp1[L].out + isOp2[L].out + isOp3[L].out === 1;

        // violation = selected comparison (each term is a single quadratic product)
        vlt[L]  <== isOp0[L].out * labLt[L].out;
        vgt[L]  <== isOp1[L].out * labGt[L].out;
        veq2[L] <== isOp2[L].out * (1 - labEq[L].out);
        veq3[L] <== isOp3[L].out * labEq[L].out;
        labViol[L] <== vlt[L] + vgt[L] + veq2[L] + veq3[L];

        // does this policy target the prescribed drug? (N_PRESC=1)
        labApplies[L] = IsEqual();
        labApplies[L].a <== labAppliesToDrug[L];
        labApplies[L].b <== prescribedDrugIds[0];

        // block = active AND violated AND applies
        labT1[L]      <== labIsActive[L] * labViol[L];
        labBlock[L]   <== labT1[L] * labApplies[L].out;
        labNoBlock[L] <== 1 - labBlock[L];
        allLabOk.in[L] <== labNoBlock[L];
    }
    policy6 <== allLabOk.out;

    // ── Final AND(P1..P6) ────────────────────────────────────────────────────────
    component finalAnd = AndN(6);
    finalAnd.in[0] <== policy1;
    finalAnd.in[1] <== policy2;
    finalAnd.in[2] <== policy3;
    finalAnd.in[3] <== policy4;
    finalAnd.in[4] <== policy5;
    finalAnd.in[5] <== policy6;
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
//   - policy parameters T   (policyDrugIds, adultMaxDosages, lab policy params)
//   - specific prescription  (stmtHash, nonce)
// stmtHash and outcome are circuit outputs and are always public.
// allergyMatrix and labValue are PRIVATE — the verifier sees only the outcome,
// not patient allergy data or lab measurements.
// Public signals: 2 outputs + 6 base inputs + 3·N_LAB lab params.
// With N_LAB=2: 2 + 6 + 6 = 14... (policyDrugIds[3]+adultMaxDosages[3] expand) → nPublic 18.
component main {public [
    doctorCredentialHash,
    validCredentialRoot,
    patientRecordRoot,
    nonce,
    policyDrugIds,
    adultMaxDosages,
    labThreshold,
    labRequiredOp,
    labAppliesToDrug
]} = PrescriptionValidation(3, 3, 1, 32, 3, 2);
