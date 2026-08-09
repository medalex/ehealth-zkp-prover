import 'reflect-metadata';
import { createHash } from 'crypto';
import { readFileSync } from 'fs';
import path from 'path';
import { buildPoseidon } from 'circomlibjs';
import { ProverService, PUB } from '../src/prover/prover.service';

// End-to-end policy enforcement tests. Each test generates a REAL Groth16 proof
// against the compiled circuit and asserts the resulting outcome, so the circuit
// (P1–P4) and the prover's witness routing are both exercised.

const MERKLE_DEPTH = 3;
const PATIENT = '00000000-0000-0000-0000-000000000001';

// Drug ids must match policyDrugIds = [105, 103, 107] in the prover.
const METFORMIN = 105;
const PENICILLIN = 103;
const AMOXICILLIN = 107;

// Same derivation as MFSSIA / prover stringToField.
function credHashOf(license: string): bigint {
  const h = createHash('sha256').update(license, 'utf8').digest('hex');
  return BigInt('0x' + h.slice(0, 62));
}

// Builds a depth-3 Poseidon Merkle tree containing credHash at leaf 0 and returns
// the membership proof — mirrors the MFSSIA physician registry.
function buildCredProof(poseidon: any, credHash: bigint) {
  const F = poseidon.F;
  const ph = (a: bigint, b: bigint) => F.toObject(poseidon([a, b]));
  const size = 1 << MERKLE_DEPTH;
  const leaves: bigint[] = Array.from({ length: size }, (_, i) => (i === 0 ? credHash : 0n));
  const tree: bigint[][] = [leaves];
  for (let d = 0; d < MERKLE_DEPTH; d++) {
    const cur = tree[d];
    const next: bigint[] = [];
    for (let i = 0; i < cur.length; i += 2) next.push(ph(cur[i], cur[i + 1]));
    tree.push(next);
  }
  const siblings: string[] = [];
  const pathBits: number[] = [];
  let idx = 0;
  for (let d = 0; d < MERKLE_DEPTH; d++) {
    const sib = idx % 2 === 0 ? idx + 1 : idx - 1;
    siblings.push(tree[d][sib].toString());
    pathBits.push(idx % 2);
    idx = Math.floor(idx / 2);
  }
  return {
    validCredentialRoot: tree[MERKLE_DEPTH][0].toString(),
    credentialSiblings: siblings,
    credentialPathBits: pathBits,
  };
}

const egfrPolicy = (op = '>=', threshold = 30) => ({
  medicationCode: 'metformin',
  clinicalCondition: 'eGFR',
  comparisonOperator: op,
  threshold,
});

const labResult = (value: number, measuredAt: string, metric = 'eGFR') => ({
  metric,
  value,
  measuredAt,
});

// A lab policy on an arbitrary drug/metric pair — for the completeness tests below.
const labPolicy = (medicationCode: string, clinicalCondition: string, op: string, threshold: number) => ({
  medicationCode,
  clinicalCondition,
  comparisonOperator: op,
  threshold,
});

// Same substance → id mapping as the prover and the MFSSIA patient-record registry.
const SUBSTANCE_IDX: Record<string, number> = { metformin: 0, penicillin: 1, amoxicillin: 2 };

// Builds the MFSSIA patient-record proof: a per-patient allergy Merkle tree with
// leaf = Poseidon(stringToField(patientId), substanceId+1) — the shared leaf contract.
function buildPatientRecord(poseidon: any, patientId: string, allergies: string[]) {
  const F = poseidon.F;
  const ph = (a: bigint, b: bigint) => F.toObject(poseidon([a, b]));
  const patientField = credHashOf(patientId.toLowerCase());
  const leafFor = (s: string): bigint => {
    const idx = SUBSTANCE_IDX[s.toLowerCase()];
    const code = idx !== undefined ? BigInt(idx + 1) : credHashOf(s);
    return ph(patientField, code);
  };

  const N_MAX = 5;
  const size = 1 << MERKLE_DEPTH;
  const active = allergies.slice(0, N_MAX);
  const leafValues: bigint[] = Array.from({ length: N_MAX }, (_, i) =>
    i < active.length ? leafFor(active[i]) : 0n);
  const padded = Array.from({ length: size }, (_, i) => (i < leafValues.length ? leafValues[i] : 0n));

  const tree: bigint[][] = [padded];
  for (let d = 0; d < MERKLE_DEPTH; d++) {
    const cur = tree[d];
    const next: bigint[] = [];
    for (let i = 0; i < cur.length; i += 2) next.push(ph(cur[i], cur[i + 1]));
    tree.push(next);
  }

  const refSiblings: string[][] = [];
  const refPathBits: number[][] = [];
  const refIsActive: number[] = [];
  for (let i = 0; i < N_MAX; i++) {
    const isActive = i < active.length ? 1 : 0;
    refIsActive.push(isActive);
    if (isActive) {
      const sib: string[] = [];
      const bits: number[] = [];
      let idx = i;
      for (let d = 0; d < MERKLE_DEPTH; d++) {
        const s = idx % 2 === 0 ? idx + 1 : idx - 1;
        sib.push(tree[d][s].toString());
        bits.push(idx % 2);
        idx = Math.floor(idx / 2);
      }
      refSiblings.push(sib);
      refPathBits.push(bits);
    } else {
      refSiblings.push(new Array(MERKLE_DEPTH).fill('0'));
      refPathBits.push(new Array(MERKLE_DEPTH).fill(0));
    }
  }

  return {
    substances: active,
    patientRecordRoot: tree[MERKLE_DEPTH][0].toString(),
    refLeaf: leafValues.map((v) => v.toString()),
    refSiblings,
    refPathBits,
    refIsActive,
  };
}

// Mirrors the MFSSIA contraindication registry: closure tree with
// leaf = Poseidon(substanceId, realDrugId, value), depth 4.
const CONTRA_DEPTH = 4;
const DRUG_IDS = [105, 103, 107]; // index 0=Metformin,1=Penicillin,2=Amoxicillin
const CONTRA = [
  [1, 0, 0],
  [0, 1, 1],
  [0, 1, 1],
];

// Builds the contraindication-closure proof for the patient's allergies vs the prescribed drug.
function buildContraindication(poseidon: any, allergies: string[], prescribedDrugId: number) {
  const F = poseidon.F;
  const ph = (arr: bigint[]) => F.toObject(poseidon(arr));
  const size = 1 << CONTRA_DEPTH;
  const leaves: bigint[] = Array.from({ length: size }, () => 0n);
  for (let s = 0; s < 3; s++) {
    for (let d = 0; d < 3; d++) {
      leaves[s * 3 + d] = ph([BigInt(s), BigInt(DRUG_IDS[d]), BigInt(CONTRA[s][d])]);
    }
  }
  const tree: bigint[][] = [leaves];
  for (let depth = 0; depth < CONTRA_DEPTH; depth++) {
    const cur = tree[depth];
    const next: bigint[] = [];
    for (let i = 0; i < cur.length; i += 2) next.push(ph([cur[i], cur[i + 1]]));
    tree.push(next);
  }

  const drugIndex = DRUG_IDS.indexOf(prescribedDrugId);
  const active = allergies.slice(0, 3);
  const contraProofs = active.map((subst) => {
    const s = SUBSTANCE_IDX[subst.toLowerCase()] ?? 0;
    const value = drugIndex >= 0 ? CONTRA[s][drugIndex] : 0;
    const siblings: string[] = [];
    const pathBits: number[] = [];
    let idx = s * 3 + drugIndex;
    for (let d = 0; d < CONTRA_DEPTH; d++) {
      const si = idx % 2 === 0 ? idx + 1 : idx - 1;
      siblings.push(tree[d][si].toString());
      pathBits.push(idx % 2);
      idx = Math.floor(idx / 2);
    }
    return { value, siblings, pathBits };
  });

  return { contraindicationRoot: tree[CONTRA_DEPTH][0].toString(), contraProofs };
}

// Mirrors the MFSSIA lab-record registry: per-patient lab Merkle tree with
// leaf = Poseidon(stringToField(patientId), stringToField(metric), floor(value)), depth 3.
const LAB_DEPTH = 3;
function buildLabRecord(
  poseidon: any,
  patientId: string,
  labResults: { metric: string; value: number; measuredAt: string }[],
) {
  const F = poseidon.F;
  const ph = (arr: bigint[]) => F.toObject(poseidon(arr));
  const patientField = credHashOf(patientId.toLowerCase());
  const size = 1 << LAB_DEPTH;
  const metricIds = labResults.map((m) => credHashOf(m.metric.toLowerCase().trim()));
  const values = labResults.map((m) => BigInt(Math.floor(m.value)));
  const leaves: bigint[] = Array.from({ length: size }, (_, i) =>
    i < labResults.length ? ph([patientField, metricIds[i], values[i]]) : 0n);

  const tree: bigint[][] = [leaves];
  for (let d = 0; d < LAB_DEPTH; d++) {
    const cur = tree[d];
    const next: bigint[] = [];
    for (let i = 0; i < cur.length; i += 2) next.push(ph([cur[i], cur[i + 1]]));
    tree.push(next);
  }

  const enriched = labResults.map((m, i) => {
    const siblings: string[] = [];
    const pathBits: number[] = [];
    let idx = i;
    for (let d = 0; d < LAB_DEPTH; d++) {
      const si = idx % 2 === 0 ? idx + 1 : idx - 1;
      siblings.push(tree[d][si].toString());
      pathBits.push(idx % 2);
      idx = Math.floor(idx / 2);
    }
    return { ...m, metricId: metricIds[i].toString(), siblings, pathBits };
  });

  return { labRecordRoot: tree[LAB_DEPTH][0].toString(), labResults: enriched };
}

describe('ProverService — policy enforcement (real Groth16 proofs)', () => {
  let service: ProverService;
  let poseidon: any;
  let cred: ReturnType<typeof buildCredProof>;
  const credHash = credHashOf('MED-LIC-2024-001');

  beforeAll(async () => {
    service = new ProverService();
    await service.onModuleInit();
    poseidon = await buildPoseidon();
    cred = buildCredProof(poseidon, credHash);
  });

  // A baseline request where every policy passes; tests override single fields.
  // The MFSSIA patient-record proof is derived from the (possibly overridden) allergies.
  const baseReq = (overrides: Record<string, unknown> = {}) => {
    const req: Record<string, unknown> = {
      doctorCredentialUal: 'urn:doctor:wilson',
      doctorCredentialHash: credHash.toString(),
      ...cred,
      patientId: PATIENT,
      drugIds: [METFORMIN],
      dosages: ['8'],
      workflowId: 77,
      allergies: [] as string[],
      labResults: [] as unknown[],
      policies: [] as unknown[],
      ...overrides,
    };
    const record = buildPatientRecord(poseidon, req.patientId as string, req.allergies as string[]);
    const contra = buildContraindication(
      poseidon,
      req.allergies as string[],
      (req.drugIds as number[])[0],
    );
    const lab = buildLabRecord(
      poseidon,
      req.patientId as string,
      req.labResults as { metric: string; value: number; measuredAt: string }[],
    );
    return { ...req, ...record, ...contra, labRecordRoot: lab.labRecordRoot, labResults: lab.labResults };
  };

  it('baseline: registered doctor, no conflicts → PASS', async () => {
    const r = await service.prove(baseReq());
    expect(r.outcome).toBe(true);
  });

  // ── P1 CredValid ────────────────────────────────────────────────────────────
  it('P1: credential not in registry tree → FAIL', async () => {
    const r = await service.prove(
      baseReq({ doctorCredentialHash: credHashOf('FORGED-LICENSE').toString() }),
    );
    expect(r.outcome).toBe(false);
  });

  // ── P2 NoContraindication ─────────────────────────────────────────────────────
  it('P2: allergy to the prescribed drug → FAIL', async () => {
    const r = await service.prove(baseReq({ allergies: ['Penicillin'], drugIds: [PENICILLIN] }));
    expect(r.outcome).toBe(false);
  });

  it('P2: β-lactam subsumption — Penicillin allergy blocks Amoxicillin → FAIL', async () => {
    const r = await service.prove(baseReq({ allergies: ['Penicillin'], drugIds: [AMOXICILLIN] }));
    expect(r.outcome).toBe(false);
  });

  it('P2: allergy to an unrelated drug → PASS', async () => {
    const r = await service.prove(baseReq({ allergies: ['Penicillin'], drugIds: [METFORMIN] }));
    expect(r.outcome).toBe(true);
  });

  // ── P3 DosageOk ───────────────────────────────────────────────────────────────
  it('P3: dosage above the policy limit → FAIL', async () => {
    const policy = { medicationCode: 'metformin', clinicalCondition: 'adult-max', comparisonOperator: '<=', threshold: 10 };
    const r = await service.prove(baseReq({ dosages: ['50'], policies: [policy] }));
    expect(r.outcome).toBe(false);
  });

  it('P3: dosage within the policy limit → PASS', async () => {
    const policy = { medicationCode: 'metformin', clinicalCondition: 'adult-max', comparisonOperator: '<=', threshold: 10 };
    const r = await service.prove(baseReq({ dosages: ['8'], policies: [policy] }));
    expect(r.outcome).toBe(true);
  });

  // ── P3 lab clause (LabPolicyOk) ─────────────────────────────────────────────────
  it('P3 (lab): eGFR below threshold (20 < 30) for Metformin → FAIL', async () => {
    const r = await service.prove(
      baseReq({
        drugIds: [METFORMIN],
        policies: [egfrPolicy('>=', 30)],
        labResults: [labResult(20, '2026-06-25T14:00:00Z')],
      }),
    );
    expect(r.outcome).toBe(false);
  });

  it('P3 (lab): eGFR at/above threshold (45 >= 30) → PASS', async () => {
    const r = await service.prove(
      baseReq({
        drugIds: [METFORMIN],
        policies: [egfrPolicy('>=', 30)],
        labResults: [labResult(45, '2026-06-25T14:00:00Z')],
      }),
    );
    expect(r.outcome).toBe(true);
  });

  it('P3 (lab): picks the most recent result — newer 20 masks older 45 → FAIL', async () => {
    const r = await service.prove(
      baseReq({
        drugIds: [METFORMIN],
        policies: [egfrPolicy('>=', 30)],
        labResults: [
          labResult(45, '2026-06-20T09:00:00Z'), // older, safe
          labResult(20, '2026-06-25T14:00:00Z'), // newer, contraindicating
        ],
      }),
    );
    expect(r.outcome).toBe(false);
  });

  it('P3 (lab): lab policy targets Metformin only — prescribing Penicillin is unaffected → PASS', async () => {
    const r = await service.prove(
      baseReq({
        drugIds: [PENICILLIN],
        policies: [egfrPolicy('>=', 30)],
        labResults: [labResult(20, '2026-06-25T14:00:00Z')],
      }),
    );
    expect(r.outcome).toBe(true);
  });

  // ── P3 lab clause: completeness of the committed policy vector ───────────────
  // The circuit enforces "a policy occupying a slot and targeting the prescribed drug must
  // be satisfied", but it cannot see a policy that was never placed in a slot. The prover
  // therefore commits the COMPLETE governed lab-policy set in canonical order; dropping or
  // reordering one is not a way to obtain outcome = 1.

  // The lab-policy part of the public input vector, in publicSignals order.
  const labVector = (publicSignals: string[]) => [
    ...PUB.labThreshold.map((i) => publicSignals[i]),
    ...PUB.labRequiredOp.map((i) => publicSignals[i]),
    ...PUB.labAppliesToDrug.map((i) => publicSignals[i]),
    ...PUB.labMetricIdPub.map((i) => publicSignals[i]),
  ];

  it('P3 (lab): more governed lab policies than N_LAB slots is an error, not a silent drop', async () => {
    await expect(
      service.prove(
        baseReq({
          drugIds: [METFORMIN],
          policies: [
            labPolicy('penicillin', 'creatinine', '<=', 2),
            labPolicy('amoxicillin', 'alt', '<=', 40),
            egfrPolicy('>=', 30), // third governed lab policy — one slot too many
          ],
          labResults: [labResult(45, '2026-06-25T14:00:00Z')],
        }),
      ),
    ).rejects.toThrow(/N_LAB=2/);
  });

  it('P3 (lab): reordering the input policies yields an identical public vector', async () => {
    const common = {
      drugIds: [METFORMIN],
      prescriptionIssuedAt: 1750000000, // pin issuanceTime so the vectors are comparable
      labResults: [labResult(45, '2026-06-25T14:00:00Z')],
    };
    const creatinine = labPolicy('penicillin', 'creatinine', '<=', 2);

    const a = await service.prove(baseReq({ ...common, policies: [egfrPolicy('>=', 30), creatinine] }));
    const b = await service.prove(baseReq({ ...common, policies: [creatinine, egfrPolicy('>=', 30)] }));

    expect(labVector(a.publicSignals)).toEqual(labVector(b.publicSignals));
    expect(a.publicSignals).toEqual(b.publicSignals);
    expect(a.outcome).toBe(true);
  });

  it('P3 (lab): a blocking policy listed last still occupies a slot and blocks → FAIL', async () => {
    const r = await service.prove(
      baseReq({
        drugIds: [METFORMIN],
        policies: [
          labPolicy('penicillin', 'creatinine', '<=', 2), // harmless, targets another drug
          egfrPolicy('>=', 30),                           // blocking, listed last
        ],
        labResults: [labResult(20, '2026-06-25T14:00:00Z')],
      }),
    );
    expect(r.outcome).toBe(false);
  });

  // ── Cryptographic soundness & binding: real Groth16 verify ───────────────────
  // These validate the proof itself (not just the computed outcome): an honest proof
  // verifies against the governance key, while tampering the public signals (S6),
  // forging the outcome bit (S5b/S11), or using a different key (S7) all fail.
  const vKey = JSON.parse(
    readFileSync(path.join(__dirname, '..', 'circuits', 'verification_key.json'), 'utf8'),
  );

  it('accept proof verifies against the governance verification key', async () => {
    const snarkjs = await import('snarkjs');
    const r = await service.prove(baseReq());
    expect(await snarkjs.groth16.verify(vKey, r.publicSignals, r.proof)).toBe(true);
  });

  it('S6: tampering a committed public signal invalidates the proof', async () => {
    const snarkjs = await import('snarkjs');
    const r = await service.prove(baseReq());
    const tampered = [...r.publicSignals];
    tampered[PUB.patientRecordRoot] = '123456789'; // forge a different patient-record root
    expect(await snarkjs.groth16.verify(vKey, tampered, r.proof)).toBe(false);
  });

  it('S5b: forging the outcome (reject → accept) does not verify', async () => {
    const snarkjs = await import('snarkjs');
    const r = await service.prove(baseReq({ allergies: ['Penicillin'], drugIds: [PENICILLIN] }));
    expect(r.outcome).toBe(false);
    const forged = [...r.publicSignals];
    forged[PUB.outcome] = '1'; // claim acceptance for a contraindicated prescription
    expect(await snarkjs.groth16.verify(vKey, forged, r.proof)).toBe(false);
  });

  it('S7: a valid proof does not verify under a different verification key', async () => {
    const snarkjs = await import('snarkjs');
    const r = await service.prove(baseReq());
    const wrongKey = JSON.parse(JSON.stringify(vKey));
    wrongKey.IC[0][0] = (BigInt(wrongKey.IC[0][0]) + 1n).toString(); // corrupt one key element
    let ok = false;
    try { ok = await snarkjs.groth16.verify(wrongKey, r.publicSignals, r.proof); } catch { ok = false; }
    expect(ok).toBe(false);
  });
});
