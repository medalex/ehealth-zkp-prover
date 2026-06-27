import { Injectable, OnModuleInit, ServiceUnavailableException } from '@nestjs/common';
import { createHash } from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import { buildPoseidon } from 'circomlibjs';
import { ProveRequestDto } from './dto/prove-request.dto';
import { VerifyRequestDto } from './dto/verify-request.dto';

// Circuit sizes — must match the compiled circom artifact.
const N_DRUGS = 3;
const N_max = 3;   // reference slot count; n_total ≈ n_cred + N_max·n_Merkle + |Pol|·n_range
const N_PRESC = 1;
const MERKLE_DEPTH = 3;
const CONTRA_DEPTH = 4;   // contraindication-closure tree depth (matches the circuit)
const N_LAB = 2;   // max lab-based clinical policy slots

// medicationCode → drugId (must align with policyDrugIds)
const DRUG_ID: Record<string, number> = {
  metformin: 105, penicillin: 103, amoxicillin: 107,
};

// Clinical lab metrics — policies on these become lab-policy slots (P6),
// everything else is folded into dosage limits (P3).
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
// outcome(0), stmtHash(1),
// doctorCredentialHash(2), validCredentialRoot(3), patientRecordRoot(4), nonce(5),
// policyDrugIds[3] → 6-8, adultMaxDosages[3] → 9-11, contraindicationRoot → 12,
// labThreshold[2] → 13-14, labRequiredOp[2] → 15-16, labAppliesToDrug[2] → 17-18
// substanceId, contraValue and labValue are PRIVATE — not visible in publicSignals
export const PUB = {
  outcome: 0,
  stmtHash: 1,
  doctorCredentialHash: 2,
  validCredentialRoot: 3,
  patientRecordRoot: 4,
  nonce: 5,
  policyDrugIds: [6, 7, 8],
  adultMaxDosages: [9, 10, 11],
  contraindicationRoot: 12,
  labThreshold: [13, 14],
  labRequiredOp: [15, 16],
  labAppliesToDrug: [17, 18],
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
  patientAge: number;
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
        '/prove and /verify will return 503 until artifacts are present.',
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
    if (!req.patientRecordRoot || !req.refLeaf || !req.refSiblings || !req.refPathBits || !req.refIsActive) {
      throw new Error('patientRecordRoot, refLeaf, refSiblings, refPathBits and refIsActive are required — fetch them from the MFSSIA patient-record registry');
    }
    const patientRecordRoot = req.patientRecordRoot;
    const refLeaf = req.refLeaf;
    const refSiblings = req.refSiblings;
    const refPathBitsArr = req.refPathBits;
    const refIsActive = req.refIsActive;

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
        // Inactive slot: refIsActive=0 leaves these unconstrained.
        substanceId.push('0');
        contraValue.push('0');
        contraSiblings.push(new Array(CONTRA_DEPTH).fill('0'));
        contraPathBits.push(new Array(CONTRA_DEPTH).fill(0));
      }
    }

    // Dosages: extract numeric part ("500mg" → "500")
    const prescribedDosages = (req.dosages ?? []).slice(0, N_PRESC).map(d => this.parseDosage(d));

    // Maximum dosages from DKG policies (lab-metric policies are routed to P6 below)
    const adultMax = new Array(N_DRUGS).fill('65535');
    const childMax = new Array(N_DRUGS).fill('65535');
    for (const p of req.policies ?? []) {
      const cond = (p.clinicalCondition ?? '').toLowerCase().trim();
      if (LAB_METRICS.has(cond)) continue;   // lab policy → handled by P6, not dosage
      const code = (p.medicationCode ?? '').toLowerCase();
      const dIdx = code.includes('metformin') ? 0
                 : code.includes('penicillin') ? 1
                 : code.includes('amoxicillin') ? 2
                 : -1;
      if (dIdx < 0) continue;
      const thresh = Math.floor(Number(p.threshold)).toString();
      if (cond.includes('child') || cond.includes('pediatric')) {
        childMax[dIdx] = thresh;
      } else {
        adultMax[dIdx] = thresh;
      }
    }

    // Lab-based clinical policies (P6) — eGFR etc.
    // A slot is activated only when the patient has a matching lab measurement;
    // missing measurement → slot inactive → no block (cannot evaluate).
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
    const labRecordSiblings: string[][] = new Array(N_LAB).fill(null).map(() => new Array(MERKLE_DEPTH).fill('0'));
    const labRecordPathBits: number[][] = new Array(N_LAB).fill(null).map(() => new Array(MERKLE_DEPTH).fill(0));

    let labSlot = 0;
    for (const p of req.policies ?? []) {
      const metric = (p.clinicalCondition ?? '').toLowerCase().trim();
      if (!LAB_METRICS.has(metric)) continue;
      if (labSlot >= N_LAB) break;
      const drugId = DRUG_ID[(p.medicationCode ?? '').toLowerCase()] ?? 0;
      if (!drugId) continue;
      // Use the most recent measurement for this metric (a patient may have several)
      const matches = labResults.filter(r => (r.metric ?? '').toLowerCase().trim() === metric);
      if (!matches.length) continue;   // no measurement on file → cannot evaluate this policy
      const lr = matches.sort((a, b) =>
        new Date(b.measuredAt ?? 0).getTime() - new Date(a.measuredAt ?? 0).getTime())[0];
      const op = OP_CODE[(p.comparisonOperator ?? '').toLowerCase().trim()] ?? 0;
      labThreshold[labSlot]     = String(Math.floor(Number(p.threshold)));
      labRequiredOp[labSlot]    = String(op);
      labAppliesToDrug[labSlot] = String(drugId);
      labValue[labSlot]         = String(Math.floor(Number(lr.value ?? 0)));
      labIsActive[labSlot]      = '1';
      // Lab-record membership for this measurement (from MFSSIA lab-record proof).
      labMetricId[labSlot]      = String(lr.metricId ?? '0');
      if (lr.siblings) labRecordSiblings[labSlot] = lr.siblings;
      if (lr.pathBits) labRecordPathBits[labSlot] = lr.pathBits;
      labSlot++;
    }

    const nowSec = Math.floor(Date.now() / 1000);
    const issuedAt = req.prescriptionIssuedAt ?? nowSec;

    // Prescription validity window (P4 TimeValid) from DKG governance (deltaMax) for the
    // prescribed drug, falling back to 7 days when no policy specifies one.
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
      adultMaxDosages: adultMax,
      credentialSiblings: credSiblings,
      credentialPathBits: credPathBits,
      prescribedDrugIds: (req.drugIds ?? []).slice(0, N_PRESC).map(String),
      prescribedDosages,
      patientAge: String(req.patientAge ?? 0),
      prescriptionTimestamp: String(issuedAt),
      validFor,   // from DKG governance deltaMax (default 7 days)
      currentTimestamp: String(nowSec),
      workflowId: String(req.workflowId ?? 0),
      childMaxDosages: childMax,
      refLeaf,
      refSiblings,
      refPathBits: refPathBitsArr.map(row => row.map(String)),
      refIsActive: refIsActive.map(String),
      labValue,
      labIsActive,
      labThreshold,
      labRequiredOp,
      labAppliesToDrug,
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
      adultMaxDosages: dto.adultMaxDosages,
      credentialSiblings: dto.credentialSiblings,
      credentialPathBits: dto.credentialPathBits.map(String),
      prescribedDrugIds: dto.prescribedDrugIds,
      prescribedDosages: dto.prescribedDosages,
      patientAge: String(dto.patientAge),
      prescriptionTimestamp: String(dto.prescriptionTimestamp),
      validFor: String(dto.validFor),
      currentTimestamp: String(dto.currentTimestamp),
      workflowId: String(dto.workflowId),
      childMaxDosages: dto.childMaxDosages,
      refLeaf: dto.refLeaf,
      refSiblings: dto.refSiblings.map(row => row.map(String)),
      refPathBits: dto.refPathBits.map(row => row.map(String)),
      refIsActive: dto.refIsActive.map(String),
      labValue: dto.labValue,
      labIsActive: dto.labIsActive.map(String),
      labThreshold: dto.labThreshold,
      labRequiredOp: dto.labRequiredOp.map(String),
      labAppliesToDrug: dto.labAppliesToDrug,
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

    if ('doctorCredentialUal' in dto) {
      // High-level format from hospital-api (ASP.NET Core camelCase JSON)
      const req = dto as HighLevelRequest;
      nonce = this.poseidonHash([BigInt(req.workflowId ?? 0)]).toString();
      input = this.buildHighLevelInput(req, nonce);
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

    return {
      proof,
      publicSignals,
      outcome: parseInt(publicSignals[PUB.outcome]) === 1,  // bool for C# System.Text.Json
      stmtHash: publicSignals[PUB.stmtHash],
      nonce,
    };
  }

  async verify(dto: VerifyRequestDto) {
    this.assertArtifacts();

    const snarkjs = await import('snarkjs');
    const valid = await snarkjs.groth16.verify(
      this.verificationKey!,
      dto.publicSignals,
      dto.proof,
    );

    return { valid };
  }
}

// Exported for hospital-api and pharmacy-api when parsing publicSignals
export { N_DRUGS, N_max, N_PRESC, MERKLE_DEPTH };
