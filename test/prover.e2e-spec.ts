import 'reflect-metadata';
import { createHash } from 'crypto';
import { buildPoseidon } from 'circomlibjs';
import { ProverService } from '../src/prover/prover.service';

// End-to-end policy enforcement tests. Each test generates a REAL Groth16 proof
// against the compiled circuit and asserts the resulting outcome, so the circuit
// (P1–P6) and the prover's witness routing are both exercised.

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

describe('ProverService — policy enforcement (real Groth16 proofs)', () => {
  let service: ProverService;
  let cred: ReturnType<typeof buildCredProof>;
  const credHash = credHashOf('MED-LIC-2024-001');

  beforeAll(async () => {
    service = new ProverService();
    await service.onModuleInit();
    const poseidon = await buildPoseidon();
    cred = buildCredProof(poseidon, credHash);
  });

  // A baseline request where every policy passes; tests override single fields.
  const baseReq = (overrides: Record<string, unknown> = {}) => ({
    doctorCredentialUal: 'urn:doctor:wilson',
    doctorCredentialHash: credHash.toString(),
    ...cred,
    patientId: PATIENT,
    drugIds: [METFORMIN],
    dosages: ['8'],
    patientAge: 40,
    workflowId: 77,
    allergies: [] as string[],
    labResults: [] as unknown[],
    policies: [] as unknown[],
    ...overrides,
  });

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

  // ── P4 TimeValid ────────────────────────────────────────────────────────────
  it('P4: prescription older than validity window → FAIL', async () => {
    const issuedLongAgo = Math.floor(Date.now() / 1000) - 800_000; // > 7 days
    const r = await service.prove(baseReq({ prescriptionIssuedAt: issuedLongAgo }));
    expect(r.outcome).toBe(false);
  });

  // ── P6 LabPolicyOk ────────────────────────────────────────────────────────────
  it('P6: eGFR below threshold (20 < 30) for Metformin → FAIL', async () => {
    const r = await service.prove(
      baseReq({
        drugIds: [METFORMIN],
        policies: [egfrPolicy('>=', 30)],
        labResults: [labResult(20, '2026-06-25T14:00:00Z')],
      }),
    );
    expect(r.outcome).toBe(false);
  });

  it('P6: eGFR at/above threshold (45 >= 30) → PASS', async () => {
    const r = await service.prove(
      baseReq({
        drugIds: [METFORMIN],
        policies: [egfrPolicy('>=', 30)],
        labResults: [labResult(45, '2026-06-25T14:00:00Z')],
      }),
    );
    expect(r.outcome).toBe(true);
  });

  it('P6: picks the most recent result — newer 20 masks older 45 → FAIL', async () => {
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

  it('P6: lab policy targets Metformin only — prescribing Penicillin is unaffected → PASS', async () => {
    const r = await service.prove(
      baseReq({
        drugIds: [PENICILLIN],
        policies: [egfrPolicy('>=', 30)],
        labResults: [labResult(20, '2026-06-25T14:00:00Z')],
      }),
    );
    expect(r.outcome).toBe(true);
  });
});
