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

// Главный шаблон.
// N_DRUGS     — количество разрешённых препаратов.
// N_max       — максимальное число референсных слотов (записей пациента),
//               каждый со своим Merkle-доказательством против root_M.
//               Определяет сложность по формуле n_total ≈ n_cred + N_max·n_Merkle + |Pol|·n_range.
// N_PRESC     — число предписаний в одном доказательстве.
// BITLEN      — битовая ширина для range-check.
// MERKLE_DEPTH — глубина дерева Меркле.
template PrescriptionValidation(N_DRUGS, N_max, N_PRESC, BITLEN, MERKLE_DEPTH) {

    // ── Приватные входы ─────────────────────────────────────────────────────────

    // Учётные данные врача
    signal input doctorCredentialHash;
    signal input credentialSiblings[MERKLE_DEPTH];
    signal input credentialPathBits[MERKLE_DEPTH];

    // Данные рецепта
    signal input prescribedDrugIds[N_PRESC];
    signal input prescribedDosages[N_PRESC];
    signal input childMaxDosages[N_DRUGS];

    signal input patientAge;
    signal input prescriptionTimestamp;
    signal input validFor;
    signal input currentTimestamp;
    signal input workflowId;

    // N_max референсных слотов записей пациента (аллергии и пр.)
    // refLeaf[i]     = Poseidon(recordId, recordType, substanceId, ...)
    // refIsActive[i] = 1 для активного слота, 0 для паддинга
    // Неактивные слоты проходят все проверки тавтологически.
    signal input refLeaf[N_max];
    signal input refSiblings[N_max][MERKLE_DEPTH];
    signal input refPathBits[N_max][MERKLE_DEPTH];
    signal input refIsActive[N_max];

    // ── Публичные входы ─────────────────────────────────────────────────────────

    // root_M — корень реестра записей (включает учётные данные врача и записи пациента)
    signal input validCredentialRoot;
    signal input nonce;
    signal input approvedDrugIds[N_DRUGS];
    signal input adultMaxDosages[N_DRUGS];
    // allergyMatrix[i][j] = 1 если аллерген из слота i противопоказан с препаратом j
    signal input allergyMatrix[N_max][N_DRUGS];

    // ── Выходы ──────────────────────────────────────────────────────────────────
    signal output outcome;
    signal output stmtHash;

    // ── Политика 1: CredValid — врач в реестре ──────────────────────────────────
    signal policy1;

    component credProof = PoseidonMerkleProof(MERKLE_DEPTH);
    credProof.leaf       <== doctorCredentialHash;
    credProof.expectedRoot <== validCredentialRoot;
    for (var d = 0; d < MERKLE_DEPTH; d++) {
        credProof.siblings[d]  <== credentialSiblings[d];
        credProof.pathBits[d]  <== credentialPathBits[d];
    }
    policy1 <== credProof.valid;

    // ── Merkle-доказательства для N_max референсных слотов ──────────────────────
    // Активный слот (refIsActive=1) обязан иметь валидное доказательство против root_M.
    // Неактивный слот (refIsActive=0) — без ограничений на доказательство.
    component refProof[N_max];
    component refActiveBool[N_max];
    component allergyBool[N_max][N_DRUGS];
    signal activeAndValid[N_max];

    for (var i = 0; i < N_max; i++) {
        refActiveBool[i] = ForceBool();
        refActiveBool[i].in <== refIsActive[i];

        refProof[i] = PoseidonMerkleProof(MERKLE_DEPTH);
        refProof[i].leaf         <== refLeaf[i];
        refProof[i].expectedRoot <== validCredentialRoot;
        for (var d = 0; d < MERKLE_DEPTH; d++) {
            refProof[i].siblings[d] <== refSiblings[i][d];
            refProof[i].pathBits[d] <== refPathBits[i][d];
        }

        // refIsActive[i] === refIsActive[i] * refProof[i].valid
        // ⟹ при refIsActive=1 требуем valid=1; при refIsActive=0 — без ограничений.
        activeAndValid[i] <== refIsActive[i] * refProof[i].valid;
        refIsActive[i] === activeAndValid[i];

        for (var j = 0; j < N_DRUGS; j++) {
            allergyBool[i][j] = ForceBool();
            allergyBool[i][j].in <== allergyMatrix[i][j];
        }
    }

    // ── Политика 2: NoContraindication — нет аллергии на выписанный препарат ────
    signal policy2;
    component rowSel[N_PRESC][N_max];
    signal activeAllergyConflict[N_PRESC][N_max];
    signal noConflictRow[N_PRESC][N_max];
    signal noAllergyPerRx[N_PRESC];
    component allNoConflict[N_PRESC];

    // ── Политика 3: DosageOk — дозировка в допустимых пределах ─────────────────
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
            childSel[p].keys[i1]   <== approvedDrugIds[i1];
            childSel[p].values[i1] <== childMaxDosages[i1];
            adultSel[p].keys[i1]   <== approvedDrugIds[i1];
            adultSel[p].values[i1] <== adultMaxDosages[i1];
        }

        for (var i2 = 0; i2 < N_max; i2++) {
            rowSel[p][i2] = SelectValue(N_DRUGS);
            rowSel[p][i2].key <== prescribedDrugIds[p];
            for (var j2 = 0; j2 < N_DRUGS; j2++) {
                rowSel[p][i2].keys[j2]   <== approvedDrugIds[j2];
                rowSel[p][i2].values[j2] <== allergyMatrix[i2][j2];
            }
            // Для активного слота: учитываем запись аллергии.
            // Для неактивного (паддинг): конфликта нет тавтологически.
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

    // ── Политика 4: TimeValid — рецепт действителен ─────────────────────────────
    signal policy4;
    component timeLe = LessEqThan(BITLEN);
    timeLe.a <== currentTimestamp;
    timeLe.b <== prescriptionTimestamp + validFor;
    policy4 <== timeLe.out;

    // ── Политика 5: NonceBind — нонс привязан к workflowId ──────────────────────
    signal policy5;
    component wfHash = Poseidon(1);
    wfHash.inputs[0] <== workflowId;

    component nonceEq = IsEqual();
    nonceEq.a <== wfHash.out;
    nonceEq.b <== nonce;
    policy5 <== nonceEq.out;

    // ── Финальный AND(P1..P5) ────────────────────────────────────────────────────
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

// Публичные входы: верификатор on-chain привязывает доказательство к:
//   - реестру учётных данных (validCredentialRoot = root_M)
//   - параметрам политики T (approvedDrugIds, allergyMatrix, adultMaxDosages)
//   - конкретному экземпляру рецепта (stmtHash, nonce)
// stmtHash и outcome — выходы схемы, всегда публичны.
// Размер allergyMatrix: N_max × N_DRUGS = 3×3 = 9 публичных сигналов.
component main {public [
    doctorCredentialHash,
    validCredentialRoot,
    nonce,
    approvedDrugIds,
    allergyMatrix,
    adultMaxDosages
]} = PrescriptionValidation(3, 3, 1, 16, 3);
