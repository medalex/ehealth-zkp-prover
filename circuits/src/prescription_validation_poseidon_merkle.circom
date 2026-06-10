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

template PrescriptionValidation(N_DRUGS, N_ALLERGIES, N_PRESC, BITLEN, MERKLE_DEPTH) {
    signal input doctorCredentialHash;
    signal input prescribedDrugIds[N_PRESC];
    signal input prescribedDosages[N_PRESC];

    signal input validCredentialRoot;
    signal input credentialSiblings[MERKLE_DEPTH];
    signal input credentialPathBits[MERKLE_DEPTH];

    signal input approvedDrugIds[N_DRUGS];
    signal input childMaxDosages[N_DRUGS];
    signal input adultMaxDosages[N_DRUGS];
    signal input allergyMatrix[N_ALLERGIES][N_DRUGS];

    signal input patientAge;
    signal input prescriptionTimestamp;
    signal input validFor;
    signal input currentTimestamp;

    signal input workflowId;
    signal input nonce;

    signal output outcome;
    signal output stmtHash;

    signal policy1;
    signal policy2;
    signal policy3;
    signal policy4;
    signal policy5;

    component allergyBool[N_ALLERGIES][N_DRUGS];
    component credProof;
    component ageIsChild;

    component childSel[N_PRESC];
    component adultSel[N_PRESC];
    component rowSel[N_PRESC][N_ALLERGIES];
    component allNoConflict[N_PRESC];
    component leChild[N_PRESC];
    component leAdult[N_PRESC];

    signal noConflictRow[N_PRESC][N_ALLERGIES];
    signal noAllergyPerRx[N_PRESC];
    signal dosageOkPerRx[N_PRESC];

    component allP2;
    component allP3;
    component timeLe;
    component wfHash;
    component nonceEq;

    component finalAnd;
    component stmtHasher;

    for (var a = 0; a < N_ALLERGIES; a++) {
        for (var i = 0; i < N_DRUGS; i++) {
            allergyBool[a][i] = ForceBool();
            allergyBool[a][i].in <== allergyMatrix[a][i];
        }
    }

    // Policy 1: doctor credential hash belongs to the valid credential Merkle root.
    credProof = PoseidonMerkleProof(MERKLE_DEPTH);
    credProof.leaf <== doctorCredentialHash;
    credProof.expectedRoot <== validCredentialRoot;
    for (var d = 0; d < MERKLE_DEPTH; d++) {
        credProof.siblings[d] <== credentialSiblings[d];
        credProof.pathBits[d] <== credentialPathBits[d];
    }
    policy1 <== credProof.valid;
    //computedCredentialRoot <== credProof.computedRoot;

    ageIsChild = LessThan(BITLEN);
    ageIsChild.a <== patientAge;
    ageIsChild.b <== 11;

    for (var p = 0; p < N_PRESC; p++) {
        childSel[p] = SelectValue(N_DRUGS);
        childSel[p].key <== prescribedDrugIds[p];

        adultSel[p] = SelectValue(N_DRUGS);
        adultSel[p].key <== prescribedDrugIds[p];

        for (var i1 = 0; i1 < N_DRUGS; i1++) {
            childSel[p].keys[i1] <== approvedDrugIds[i1];
            childSel[p].values[i1] <== childMaxDosages[i1];

            adultSel[p].keys[i1] <== approvedDrugIds[i1];
            adultSel[p].values[i1] <== adultMaxDosages[i1];
        }

        for (var a2 = 0; a2 < N_ALLERGIES; a2++) {
            rowSel[p][a2] = SelectValue(N_DRUGS);
            rowSel[p][a2].key <== prescribedDrugIds[p];

            for (var i2 = 0; i2 < N_DRUGS; i2++) {
                rowSel[p][a2].keys[i2] <== approvedDrugIds[i2];
                rowSel[p][a2].values[i2] <== allergyMatrix[a2][i2];
            }
            noConflictRow[p][a2] <== 1 - rowSel[p][a2].selected;
        }

        allNoConflict[p] = AndN(N_ALLERGIES);
        for (var a3 = 0; a3 < N_ALLERGIES; a3++) {
            allNoConflict[p].in[a3] <== noConflictRow[p][a3];
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

    allP2 = AndN(N_PRESC);
    allP3 = AndN(N_PRESC);
    for (var p2 = 0; p2 < N_PRESC; p2++) {
        allP2.in[p2] <== noAllergyPerRx[p2];
        allP3.in[p2] <== dosageOkPerRx[p2];
    }
    policy2 <== allP2.out;
    policy3 <== allP3.out;

    timeLe = LessEqThan(BITLEN);
    timeLe.a <== currentTimestamp;
    timeLe.b <== prescriptionTimestamp + validFor;
    policy4 <== timeLe.out;

    wfHash = Poseidon(1);
    wfHash.inputs[0] <== workflowId;

    nonceEq = IsEqual();
    nonceEq.a <== wfHash.out;
    nonceEq.b <== nonce;
    policy5 <== nonceEq.out;

    finalAnd = AndN(5);
    finalAnd.in[0] <== policy1;
    finalAnd.in[1] <== policy2;
    finalAnd.in[2] <== policy3;
    finalAnd.in[3] <== policy4;
    finalAnd.in[4] <== policy5;
    outcome <== finalAnd.out;

    stmtHasher = Poseidon(2 * N_PRESC + 2);
    stmtHasher.inputs[0] <== doctorCredentialHash;
    stmtHasher.inputs[1] <== nonce;
    for (var k = 0; k < N_PRESC; k++) {
        stmtHasher.inputs[2 + k]           <== prescribedDrugIds[k];
        stmtHasher.inputs[2 + N_PRESC + k] <== prescribedDosages[k];
    }
    stmtHash <== stmtHasher.out;
}

// Public inputs allow the on-chain verifier to bind the proof to:
// - the governance-approved credential registry (validCredentialRoot)
// - the governance-approved theory T parameters (approvedDrugIds, allergyMatrix, adultMaxDosages)
// - the specific prescription instance (stmtHash, nonce)
// stmtHash and prescriptionValid are signal outputs and are always public.
component main {public [
    doctorCredentialHash,
    validCredentialRoot,
    nonce,
    approvedDrugIds,
    allergyMatrix,
    adultMaxDosages
]} = PrescriptionValidation(4, 3, 2, 16, 3);


/*
INPUT =
{
  "doctorCredentialHash": "555",
  "prescribedDrugIds": ["101", "104"],
  "prescribedDosages": ["8", "2"],

  "validCredentialRoot": "12637775194496995754117307235330377055135569056804320597148279303980524724247",
  "credentialSiblings": [
    "666",
    "8729492946723542771608110226099589081116106357422917950961108651628306410978",
    "2627613426887678919670906595223549159912332087418882198813349531614684120136"
  ],
  "credentialPathBits": [
    "0",
    "0",
    "1"
  ],

  "approvedDrugIds": ["101", "102", "103", "104"],
  "childMaxDosages": ["10", "5", "8", "2"],
  "adultMaxDosages": ["20", "10", "16", "4"],

  "allergyMatrix": [
    ["0", "0", "1", "0"],
    ["0", "0", "0", "0"],
    ["0", "0", "0", "0"]
  ],

  "patientAge": "12",
  "prescriptionTimestamp": "1000",
  "validFor": "50",
  "currentTimestamp": "1030",

  "workflowId": "77",
  "nonce": "TODO: recompute as Poseidon(1)(77)"
}


*/