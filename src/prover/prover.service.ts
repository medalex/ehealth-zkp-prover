import { Injectable, OnModuleInit, ServiceUnavailableException } from '@nestjs/common';
import { createHash } from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import { buildPoseidon } from 'circomlibjs';
import { ProveRequestDto } from './dto/prove-request.dto';

// Circuit sizes — must match the compiled circom artifact.
const N_DRUGS = 3;
const N_max = 5;   // reference slot count; n_total ≈ n_cred + N_max·n_Merkle + |Pol|·n_range
const N_PRESC = 1;
const MERKLE_DEPTH = 3;
const CONTRA_DEPTH = 4;   // contraindication-closure tree depth (matches the circuit)
const LAB_DEPTH = 3;      // per-patient lab-record tree depth (matches the circuit)
const N_LAB = 2;   // max lab-based clinical policy slots

// medicationCode → drugId (must align with policyDrugIds)
const DRUG_ID: Record<string, number> = {
  metformin: 105, penicillin: 103, amoxicillin: 107,
};

// Clinical lab metrics — policies on these become lab-policy slots (P3 lab clause),
// everything else is folded into dosage limits (P3 dosage clause).
const LAB_METRICS = new Set(['egfr', 'creatinine', 'alt', 'ast', 'inr']);

// DKG comparison operator → circuit op code for the required (safe) condition:
// 0=GTE, 1=LTE, 2=EQ, 3=NEQ
const OP_CODE: Record<string, number> = {
  '>=': 0, 'gte': 0, '>': 0,
  '<=': 1, 'lte': 1, '<': 1,
  '=': 2, '==': 2, 'eq': 2,
  '!=': 3, 'neq': 3,
};

// Allergen → 0-based drug index mapping.
// policyDrugIds = [105, 103, 107]:
//   j=0 → Metformin (drugId 105)
//   j=1 → Penicillin (drugId 103)
//   j=2 → Amoxicillin (drugId 107)
const SUBSTANCE_IDX: Record<string, number> = {
  'Metformin':   0, 'metformin':   0,
  'Penicillin':  1, 'penicillin':  1,
  'Amoxicillin': 2, 'amoxicillin': 2,
};

// β-lactam subsumption (Penicillin allergy ⟹ Amoxicillin) now lives in the
// MFSSIA contraindication closure committed in DKG, not in the prover.

// Public signal indices (outputs first, then public inputs in declaration order):
// outcome(0), stmtHash(1), issuanceTime(2), validFor(3),
// validCredentialRoot(4), patientRecordRoot(5), nonce(6),
// policyDrugIds[3] → 7-9, maxDosages[3] → 10-12, contraindicationRoot → 13,
// labRecordRoot → 14, labThreshold[2] → 15-16, labRequiredOp[2] → 17-18, labAppliesToDrug[2] → 19-20,
// labMetricIdPub[2] → 21-22
// doctorCredentialHash, substanceId, contraValue and labValue are PRIVATE — not in publicSignals
export const PUB = {
  outcome: 0,
  stmtHash: 1,
  issuanceTime: 2,
  validFor: 3,
  validCredentialRoot: 4,
  patientRecordRoot: 5,
  nonce: 6,
  policyDrugIds: [7, 8, 9],
  maxDosages: [10, 11, 12],
  contraindicationRoot: 13,
  labRecordRoot: 14,
  labThreshold: [15, 16],
  labRequiredOp: [17, 18],
  labAppliesToDrug: [19, 20],
  labMetricIdPub: [21, 22],
} as const;

// High-level request from hospital-api (ASP.NET Core serializes to camelCase)
interface HighLevelRequest {
  doctorCredentialUal: string;
  // MFSSIA registry data: credential hash + Merkle proof against validCredentialRoot
  doctorCredentialHash?: string;
  validCredentialRoot?: string;
  credentialSiblings?: string[];
  credentialPathBits?: number[];
  patientId: string;
  drugIds: number[];
  dosages: string[];
  workflowId: number;
  prescriptionIssuedAt?: number;
  allergies: string[];
  // MFSSIA patient-record proof (allergy tree built from DKG, anchored). When present,
  // the prover uses these instead of building the tree locally.
  substances?: string[];
  patientRecordRoot?: string;
  refLeaf?: string[];
  refSiblings?: string[][];
  refPathBits?: number[][];
  refIsActive?: number[];
  // Allergy-count commitment from the MFSSIA patient-record proof: the circuit derives
  // slot activation from allergyCount and proves the zero leaf sits at that index, so the
  // prover no longer gets to say which allergy slots count.
  allergyCount?: number;
  paddingSiblings?: string[];
  paddingPathBits?: number[];
  // MFSSIA contraindication-closure proof: root + per-active-slot membership for
  // (substanceId, prescribedDrug) → value. Aligned with substances order.
  contraindicationRoot?: string;
  contraProofs?: { value: number; siblings: string[]; pathBits: number[] }[];
  // MFSSIA lab-record proof: root + per-measurement membership (leaf bound to patient + metric).
  labRecordRoot?: string;
  labResults: { metric?: string; value?: number; measuredAt?: string; metricId?: string; siblings?: string[]; pathBits?: number[] }[];
  policies: { medicationCode: string; clinicalCondition: string; comparisonOperator: string; threshold: number; deltaMax?: number }[];
}

@Injectable()
export class ProverService implements OnModuleInit {
  private poseidon: Awaited<ReturnType<typeof buildPoseidon>>;
  private verificationKey: object | null = null;

  private readonly circuitsDir = path.join(process.cwd(), 'circuits');
  private readonly wasmPath = path.join(this.circuitsDir, 'prescription_validation_poseidon_merkle.wasm');
  private readonly zkeyPath = path.join(this.circuitsDir, 'circuit_final.zkey');
  private readonly vkeyPath = path.join(this.circuitsDir, 'verification_key.json');

  async onModuleInit() {
    this.poseidon = await buildPoseidon();

    if (fs.existsSync(this.vkeyPath)) {
      this.verificationKey = JSON.parse(fs.readFileSync(this.vkeyPath, 'utf-8'));
      console.log('[ZKP Prover] Circuit artifacts loaded from', this.circuitsDir);
    } else {
      console.warn(
        '[ZKP Prover] Circuit artifacts not found in', this.circuitsDir,
        '— run the trusted setup first (see scripts/setup.sh).',
        '/prove will return 503 until artifacts are present.',
      );
    }
  }

  private poseidonHash(inputs: bigint[]): bigint {
    return this.poseidon.F.toObject(this.poseidon(inputs));
  }

  // Deterministic string → BN254 field element (31 bytes = 248 bits < 254-bit prime)
  private stringToField(s: string): bigint {
    const h = createHash('sha256').update(s, 'utf8').digest('hex');
    return BigInt('0x' + h.slice(0, 62));
  }

  // Extracts the first integer from a dosage string ("500mg" → "500")
  private parseDosage(s: string): string {
    const m = (s ?? '').match(/\d+/);
    return m ? m[0] : '0';
  }

  // The governed lab-policy set that goes into the public inputs.
  //
  // This vector is COMPLETE and CANONICALLY ORDERED, never a per-request selection. The
  // circuit can only enforce "a policy occupying a slot and targeting the prescribed drug
  // must be satisfied" — it cannot see a policy that was never placed in a slot. Dropping
  // a blocking policy (past a slot limit, or by ordering the request adversarially) would
  // therefore yield outcome = 1: the same opt-out the labIsActive fix closed, one level up.
  //
  // The defence is off-circuit and lives here: the verifier compares
  // (labThreshold, labRequiredOp, labAppliesToDrug, labMetricIdPub) as a WHOLE against the
  // DKG-committed policy set, and a fixed canonical order (medicationCode, then
  // clinicalCondition) makes that comparison exact. An omitted or reordered policy changes
  // the public vector and is rejected by the verifier. Overflow is a hard error, never a
  // silent truncation.
  private selectLabPolicies(policies: HighLevelRequest['policies']): HighLevelRequest['policies'] {
    const norm = (s?: string) => (s ?? '').toLowerCase().trim();
    const labPolicies = (policies ?? []).filter(
      (p) => LAB_METRICS.has(norm(p.clinicalCondition)) && (DRUG_ID[norm(p.medicationCode)] ?? 0) !== 0,
    );

    // Tie-break down to the full policy identity: two-sided ranges on one metric (eGFR >= 30
    // AND eGFR <= 120) are routine clinically, and they tie on drug + metric. A tie leaves
    // the order to the caller's input, which is exactly what canonical ordering must remove.
    labPolicies.sort(
      (a, b) =>
        norm(a.medicationCode).localeCompare(norm(b.medicationCode)) ||
        norm(a.clinicalCondition).localeCompare(norm(b.clinicalCondition)) ||
        norm(a.comparisonOperator).localeCompare(norm(b.comparisonOperator)) ||
        Number(a.threshold) - Number(b.threshold),
    );

    if (labPolicies.length > N_LAB) {
      throw new Error(
        `${labPolicies.length} governed lab policies supplied but the circuit has only N_LAB=${N_LAB} ` +
        `lab-policy slots. Truncating would silently drop a policy the verifier expects in the public ` +
        `vector (and could drop a blocking one), so no proof is generated — recompile the circuit with ` +
        `a larger N_LAB and redo the trusted setup.`,
      );
    }
    return labPolicies;
  }

  // Transforms high-level hospital-api request into circuit-level inputs
  private buildHighLevelInput(req: HighLevelRequest, nonce: string): Record<string, unknown> {
    const allergies = req.allergies ?? [];
    // drugId 105 = Metformin (idx 0), drugId 103 = Penicillin (idx 1), drugId 107 = Amoxicillin (idx 2)
    const policyDrugIds = ['105', '103', '107'];

    // Credential hash: use MFSSIA registry value if provided, otherwise derive from UAL
    const doctorCredentialHash = req.doctorCredentialHash
      ? BigInt(req.doctorCredentialHash)
      : this.stringToField(req.doctorCredentialUal ?? '');

    // Physician credential: root + proof come from MFSSIA (required).
    if (!req.validCredentialRoot || !req.credentialSiblings || !req.credentialPathBits) {
      throw new Error('validCredentialRoot, credentialSiblings and credentialPathBits are required — fetch them from MFSSIA physician registry');
    }
    const validCredentialRoot = req.validCredentialRoot;
    const credSiblings = req.credentialSiblings;
    const credPathBits = req.credentialPathBits.map(String);

    // Patient allergy record: root + Merkle proof come from the MFSSIA patient-record
    // registry (built from DKG allergies, leaf bound to patientId). Required — MFSSIA is
    // the authoritative source; the prover does not fabricate the patient record locally.
    if (!req.patientRecordRoot || !req.refLeaf || !req.refSiblings || !req.refPathBits) {
      throw new Error('patientRecordRoot, refLeaf, refSiblings and refPathBits are required — fetch them from the MFSSIA patient-record registry');
    }
    if (req.allergyCount === undefined || !req.paddingSiblings || !req.paddingPathBits) {
      throw new Error('allergyCount, paddingSiblings and paddingPathBits are required — fetch them from the MFSSIA patient-record registry (the circuit derives slot activation from the committed allergy count)');
    }
    // Truncating here is exactly the attack the count commitment closes: the dropped
    // allergies would simply not be checked, and the proof would still verify.
    if (allergies.length > N_max) {
      throw new Error(
        `patient has ${allergies.length} allergies but the circuit has only N_max=${N_max} slots — ` +
        `truncating would silently skip the rest, so no proof is generated. Recompile the circuit ` +
        `with a larger N_max and redo the trusted setup.`,
      );
    }
    const patientRecordRoot = req.patientRecordRoot;
    const refLeaf = req.refLeaf;
    const refSiblings = req.refSiblings;
    const refPathBitsArr = req.refPathBits;
    const allergyCount = req.allergyCount;
    const paddingSiblings = req.paddingSiblings;
    const paddingPathBits = req.paddingPathBits;

    // Committed contraindication: substanceId is bound to refLeaf, and the conflict value
    // comes from the MFSSIA contraindication closure (required — not fabricated locally).
    if (!req.contraindicationRoot || !req.contraProofs) {
      throw new Error('contraindicationRoot and contraProofs are required — fetch them from the MFSSIA contraindication registry');
    }
    const contraindicationRoot = req.contraindicationRoot;
    const patientField = this.stringToField((req.patientId ?? '').toLowerCase()).toString();
    const subs = req.substances ?? allergies;
    const substanceId: string[] = [];
    const contraValue: string[] = [];
    const contraSiblings: string[][] = [];
    const contraPathBits: number[][] = [];
    for (let i = 0; i < N_max; i++) {
      const cp = req.contraProofs[i];
      if (i < subs.length && cp) {
        substanceId.push(String(SUBSTANCE_IDX[subs[i]] ?? 0));
        contraValue.push(String(cp.value));
        contraSiblings.push(cp.siblings);
        contraPathBits.push(cp.pathBits);
      } else {
        // Padding slot (index >= allergyCount): the circuit derives refIsActive = 0 there,
        // which leaves these unconstrained.
        substanceId.push('0');
        contraValue.push('0');
        contraSiblings.push(new Array(CONTRA_DEPTH).fill('0'));
        contraPathBits.push(new Array(CONTRA_DEPTH).fill(0));
      }
    }

    // Dosages: extract numeric part ("500mg" → "500")
    const prescribedDosages = (req.dosages ?? []).slice(0, N_PRESC).map(d => this.parseDosage(d));

    // Maximum dosages from DKG policies (lab-metric policies are routed to the P3 lab clause below).
    // Single governance-approved maximum per drug (age stratification removed).
    const maxDosages = new Array(N_DRUGS).fill('65535');
    for (const p of req.policies ?? []) {
      const cond = (p.clinicalCondition ?? '').toLowerCase().trim();
      if (LAB_METRICS.has(cond)) continue;   // lab policy → handled by the P3 lab clause, not dosage
      const code = (p.medicationCode ?? '').toLowerCase();
      const dIdx = code.includes('metformin') ? 0
                 : code.includes('penicillin') ? 1
                 : code.includes('amoxicillin') ? 2
                 : -1;
      if (dIdx < 0) continue;
      maxDosages[dIdx] = Math.floor(Number(p.threshold)).toString();
    }

    // Lab-based clinical policies (P3 lab clause) — eGFR etc.
    // Slot activation is fixed by the circuit: labIsActive[L] === (labAppliesToDrug[L] ==
    // prescribedDrugIds[0]). A slot whose policy targets another drug MUST be inactive, and a
    // slot whose policy targets the prescribed drug MUST be active and carry a lab-record
    // membership proof — the prover can no longer opt out of a policy that applies.
    if (!req.labRecordRoot) {
      throw new Error('labRecordRoot is required — fetch it from the MFSSIA lab-record registry');
    }
    const labRecordRoot = req.labRecordRoot;
    const labResults = req.labResults ?? [];
    const labThreshold = new Array(N_LAB).fill('0');
    const labRequiredOp = new Array(N_LAB).fill('0');
    const labAppliesToDrug = new Array(N_LAB).fill('0');
    const labValue = new Array(N_LAB).fill('0');
    const labIsActive = new Array(N_LAB).fill('0');
    const labMetricId = new Array(N_LAB).fill('0');
    // PUBLIC: the metric each policy governs, derived from the POLICY (clinicalCondition),
    // never from the measurement — otherwise labMetricId === labMetricIdPub is vacuous.
    const labMetricIdPub = new Array(N_LAB).fill('0');
    const labRecordSiblings: string[][] = new Array(N_LAB).fill(null).map(() => new Array(LAB_DEPTH).fill('0'));
    const labRecordPathBits: number[][] = new Array(N_LAB).fill(null).map(() => new Array(LAB_DEPTH).fill(0));

    const prescribedDrugId = (req.drugIds ?? [])[0];
    let labSlot = 0;
    // Complete governed set in canonical order — see selectLabPolicies. Nothing is skipped
    // or truncated here, so slot L always holds the L-th policy of that committed vector.
    for (const p of this.selectLabPolicies(req.policies)) {
      const metric = (p.clinicalCondition ?? '').toLowerCase().trim();
      const drugId = DRUG_ID[(p.medicationCode ?? '').toLowerCase()] ?? 0;
      const op = OP_CODE[(p.comparisonOperator ?? '').toLowerCase().trim()] ?? 0;
      // Public policy parameters — committed regardless of whether the slot is active.
      labThreshold[labSlot]     = String(Math.floor(Number(p.threshold)));
      labRequiredOp[labSlot]    = String(op);
      labAppliesToDrug[labSlot] = String(drugId);
      labMetricIdPub[labSlot]   = this.stringToField(metric).toString();
      // Private metric id is pinned to the public one (circuit: labMetricId === labMetricIdPub);
      // it is also what the MFSSIA lab-record leaf uses, so membership still verifies.
      labMetricId[labSlot]      = labMetricIdPub[labSlot];

      // Use the most recent measurement for this metric (a patient may have several)
      const matches = labResults.filter(r => (r.metric ?? '').toLowerCase().trim() === metric);
      const lr = matches.sort((a, b) =>
        new Date(b.measuredAt ?? 0).getTime() - new Date(a.measuredAt ?? 0).getTime())[0];

      if (drugId === prescribedDrugId) {
        // Policy applies → the circuit forces labIsActive = 1, which requires a lab-record
        // membership proof. Without a measurement no witness exists; fail loudly instead of
        // silently dropping the policy (which the old `continue` did).
        if (!lr) {
          throw new Error(
            `Lab policy "${p.clinicalCondition}" applies to the prescribed drug (${drugId}) but the ` +
            `patient has no ${metric} measurement in the MFSSIA lab record — cannot build a witness ` +
            `(the circuit requires an active, Merkle-proved measurement for every applicable lab policy).`,
          );
        }
        labValue[labSlot]    = String(Math.floor(Number(lr.value ?? 0)));
        labIsActive[labSlot] = '1';
        if (lr.siblings) labRecordSiblings[labSlot] = lr.siblings;
        if (lr.pathBits) labRecordPathBits[labSlot] = lr.pathBits;
      } else {
        // Policy targets a different drug → labApplies = 0, so the slot must stay inactive.
        // labValue/siblings are then unconstrained; keep them at the zero padding.
        labIsActive[labSlot] = '0';
      }
      labSlot++;
    }

    const nowSec = Math.floor(Date.now() / 1000);
    const issuedAt = req.prescriptionIssuedAt ?? nowSec;

    // Prescription validity window from DKG governance (deltaMax) for the prescribed
    // drug, falling back to 7 days. Exposed as a public input + bound into stmtHash;
    // the freshness check (now <= issuanceTime + validFor) is done by the pharmacy.
    const prescribedId = (req.drugIds ?? [])[0];
    const drugName = Object.keys(DRUG_ID).find(k => DRUG_ID[k] === prescribedId);
    let validFor = '604800'; // 7 days default
    for (const p of req.policies ?? []) {
      if (drugName && (p.medicationCode ?? '').toLowerCase().includes(drugName) && p.deltaMax) {
        validFor = String(Math.floor(Number(p.deltaMax)));
        break;
      }
    }

    return {
      doctorCredentialHash: doctorCredentialHash.toString(),
      validCredentialRoot,
      patientRecordRoot,
      nonce,
      policyDrugIds,
      contraindicationRoot,
      patientField,
      substanceId,
      contraValue,
      contraSiblings,
      contraPathBits: contraPathBits.map(row => row.map(String)),
      maxDosages,
      credentialSiblings: credSiblings,
      credentialPathBits: credPathBits,
      prescribedDrugIds: (req.drugIds ?? []).slice(0, N_PRESC).map(String),
      prescribedDosages,
      issuanceTime: String(issuedAt),
      validFor,   // from DKG governance deltaMax (default 7 days)
      workflowId: String(req.workflowId ?? 0),
      refLeaf,
      refSiblings,
      refPathBits: refPathBitsArr.map(row => row.map(String)),
      // refIsActive is DERIVED in-circuit from allergyCount — deliberately not supplied.
      allergyCount: String(allergyCount),
      paddingSiblings,
      paddingPathBits: paddingPathBits.map(String),
      labValue,
      labIsActive,
      labThreshold,
      labRequiredOp,
      labAppliesToDrug,
      labMetricIdPub,
      labRecordRoot,
      labMetricId,
      labRecordSiblings,
      labRecordPathBits: labRecordPathBits.map(row => row.map(String)),
    };
  }

  // Builds circuit input from low-level DTO (direct circuit-level fields)
  private buildInput(dto: ProveRequestDto, nonce: string): Record<string, unknown> {
    return {
      doctorCredentialHash: dto.doctorCredentialHash,
      validCredentialRoot: dto.validCredentialRoot,
      nonce,
      policyDrugIds: dto.policyDrugIds,
      contraindicationRoot: dto.contraindicationRoot,
      patientField: dto.patientField,
      substanceId: dto.substanceId.map(String),
      contraValue: dto.contraValue.map(String),
      contraSiblings: dto.contraSiblings.map(row => row.map(String)),
      contraPathBits: dto.contraPathBits.map(row => row.map(String)),
      maxDosages: dto.maxDosages,
      credentialSiblings: dto.credentialSiblings,
      credentialPathBits: dto.credentialPathBits.map(String),
      prescribedDrugIds: dto.prescribedDrugIds,
      prescribedDosages: dto.prescribedDosages,
      issuanceTime: String(dto.issuanceTime),
      validFor: String(dto.validFor),
      workflowId: String(dto.workflowId),
      refLeaf: dto.refLeaf,
      refSiblings: dto.refSiblings.map(row => row.map(String)),
      refPathBits: dto.refPathBits.map(row => row.map(String)),
      allergyCount: String(dto.allergyCount),
      paddingSiblings: dto.paddingSiblings,
      paddingPathBits: dto.paddingPathBits.map(String),
      labValue: dto.labValue,
      labIsActive: dto.labIsActive.map(String),
      labThreshold: dto.labThreshold,
      labRequiredOp: dto.labRequiredOp.map(String),
      labAppliesToDrug: dto.labAppliesToDrug,
      labMetricIdPub: dto.labMetricIdPub,
      labRecordRoot: dto.labRecordRoot,
      labMetricId: dto.labMetricId,
      labRecordSiblings: dto.labRecordSiblings.map(row => row.map(String)),
      labRecordPathBits: dto.labRecordPathBits.map(row => row.map(String)),
    };
  }

  private assertArtifacts(): void {
    const missing: string[] = [];
    if (!fs.existsSync(this.wasmPath)) missing.push('prescription_validation_poseidon_merkle.wasm');
    if (!fs.existsSync(this.zkeyPath)) missing.push('circuit_final.zkey');
    if (!this.verificationKey) missing.push('verification_key.json');
    if (missing.length > 0) {
      throw new ServiceUnavailableException(
        `Circuit artifacts missing in circuits/: ${missing.join(', ')}. Run scripts/setup.sh first.`,
      );
    }
  }

  async prove(dto: ProveRequestDto | HighLevelRequest | Record<string, unknown>) {
    this.assertArtifacts();

    let nonce: string;
    let input: Record<string, unknown>;
    let highReq: HighLevelRequest | null = null;

    if ('doctorCredentialUal' in dto) {
      // High-level format from hospital-api (ASP.NET Core camelCase JSON)
      highReq = dto as HighLevelRequest;
      nonce = this.poseidonHash([BigInt(highReq.workflowId ?? 0)]).toString();
      input = this.buildHighLevelInput(highReq, nonce);
    } else {
      // Low-level format (direct circuit inputs)
      const req = dto as ProveRequestDto;
      nonce = this.poseidonHash([BigInt(req.workflowId ?? 0)]).toString();
      input = this.buildInput(req, nonce);
    }

    const snarkjs = await import('snarkjs');
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
      input,
      this.wasmPath,
      this.zkeyPath,
    );

    const outcome = parseInt(publicSignals[PUB.outcome]) === 1;

    return {
      proof,
      publicSignals,
      outcome, // bool for C# System.Text.Json
      stmtHash: publicSignals[PUB.stmtHash],
      nonce,
      // Diagnostic, prescribing-side only: WHY the prescription was rejected. Derived from
      // the witness the doctor already holds — NOT part of the proof / public signals, so the
      // pharmacy still sees only the binary outcome.
      reasons: !outcome && highReq ? this.computeReasons(highReq) : [],
    };
  }

  // Re-derives the human-readable rejection reasons from the high-level request (witness).
  // Mirrors P2/P3 (contraindication, dosage and lab clauses) at the semantic level for clinician feedback; never leaves the
  // prescribing side and is not encoded in the proof.
  private computeReasons(req: HighLevelRequest): string[] {
    const reasons: string[] = [];
    const drugId = (req.drugIds ?? [])[0];
    const drugName = Object.keys(DRUG_ID).find((k) => DRUG_ID[k] === drugId) ?? `drug ${drugId}`;
    const cap = (s: string) => s.charAt(0).toUpperCase() + s.slice(1);

    // P2 — committed contraindication: an active allergy contraindicates the prescribed drug.
    const substances = req.substances ?? req.allergies ?? [];
    (req.contraProofs ?? []).forEach((cp, i) => {
      if (cp?.value === 1) {
        reasons.push(`Contraindication: ${substances[i] ?? `substance ${i}`} allergy contraindicates ${cap(drugName)}`);
      }
    });

    // P3 — dosage above the governance maximum for the prescribed drug.
    const dose = Number(this.parseDosage((req.dosages ?? [])[0] ?? '0'));
    let max = Number.POSITIVE_INFINITY;
    for (const p of req.policies ?? []) {
      const cond = (p.clinicalCondition ?? '').toLowerCase().trim();
      if (LAB_METRICS.has(cond)) continue;
      if (!(p.medicationCode ?? '').toLowerCase().includes(drugName)) continue;
      max = Math.floor(Number(p.threshold));
    }
    if (Number.isFinite(max) && dose > max) {
      reasons.push(`Dosage ${dose} exceeds the maximum ${max} for ${cap(drugName)}`);
    }

    // P3 lab clause — lab policy violated for the prescribed drug (most recent measurement).
    for (const p of req.policies ?? []) {
      const metric = (p.clinicalCondition ?? '').toLowerCase().trim();
      if (!LAB_METRICS.has(metric)) continue;
      if (DRUG_ID[(p.medicationCode ?? '').toLowerCase()] !== drugId) continue;
      const matches = (req.labResults ?? []).filter((r) => (r.metric ?? '').toLowerCase().trim() === metric);
      if (!matches.length) continue;
      const lr = matches.sort((a, b) =>
        new Date(b.measuredAt ?? 0).getTime() - new Date(a.measuredAt ?? 0).getTime())[0];
      const val = Math.floor(Number(lr.value ?? 0));
      const thr = Math.floor(Number(p.threshold));
      const op = OP_CODE[(p.comparisonOperator ?? '').toLowerCase().trim()] ?? 0;
      const safe = op === 0 ? val >= thr : op === 1 ? val <= thr : op === 2 ? val === thr : val !== thr;
      if (!safe) {
        const sym = ['>=', '<=', '==', '!='][op];
        reasons.push(`Lab: ${p.clinicalCondition} ${val} fails policy (requires ${sym} ${thr}) for ${cap(drugName)}`);
      }
    }

    if (!reasons.length) {
      reasons.push('One or more policy checks failed (e.g. credential not in registry)');
    }
    return reasons;
  }

}

// Exported for hospital-api and pharmacy-api when parsing publicSignals
export { N_DRUGS, N_max, N_PRESC, MERKLE_DEPTH };
