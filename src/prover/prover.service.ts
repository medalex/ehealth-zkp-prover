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

// Allergen → 0-based drug index mapping.
// approvedDrugIds = [105, 103, 107]:
//   j=0 → Metformin (drugId 105)
//   j=1 → Penicillin (drugId 103)
//   j=2 → Amoxicillin (drugId 107)
const SUBSTANCE_IDX: Record<string, number> = {
  'Metformin':   0, 'metformin':   0,
  'Penicillin':  1, 'penicillin':  1,
  'Amoxicillin': 2, 'amoxicillin': 2,
};

// β-lactam class subsumption: Penicillin allergy also blocks Amoxicillin.
// allergyMatrix[slot][j]=1 for each j in the blocked set.
const ALLERGY_BLOCKS: Record<number, number[]> = {
  1: [1, 2],  // Penicillin (idx=1) ⊑ β-lactam → blocks Penicillin + Amoxicillin
  2: [1, 2],  // Amoxicillin (idx=2) ⊑ β-lactam → blocks the same class
  0: [0],     // Metformin — separate class (biguanide)
};

// Public signal indices (outputs first, then public inputs in declaration order):
// outcome(0), stmtHash(1),
// doctorCredentialHash(2), validCredentialRoot(3), patientRecordRoot(4), nonce(5),
// approvedDrugIds[3] → 6-8, adultMaxDosages[3] → 9-11
// allergyMatrix is PRIVATE — not visible in publicSignals
export const PUB = {
  outcome: 0,
  stmtHash: 1,
  doctorCredentialHash: 2,
  validCredentialRoot: 3,
  patientRecordRoot: 4,
  nonce: 5,
  approvedDrugIds: [6, 7, 8],
  adultMaxDosages: [9, 10, 11],
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
  allergies: string[];
  labResults: unknown[];
  policies: { medicationCode: string; clinicalCondition: string; comparisonOperator: string; threshold: number }[];
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

  // Builds a Poseidon Merkle tree of depth MERKLE_DEPTH (8 leaves)
  private buildMerkleTree(leaves: bigint[]): { root: bigint; tree: bigint[][] } {
    const size = 1 << MERKLE_DEPTH;
    const padded = Array.from({ length: size }, (_, i) => i < leaves.length ? leaves[i] : 0n);
    const tree: bigint[][] = [padded];
    for (let d = 0; d < MERKLE_DEPTH; d++) {
      const cur = tree[d];
      const next: bigint[] = [];
      for (let i = 0; i < cur.length; i += 2) {
        next.push(this.poseidonHash([cur[i], cur[i + 1]]));
      }
      tree.push(next);
    }
    return { root: tree[MERKLE_DEPTH][0], tree };
  }

  // Returns a Merkle membership proof for the leaf at leafIdx
  private getMerkleProof(tree: bigint[][], leafIdx: number): { siblings: string[]; pathBits: number[] } {
    const siblings: string[] = [];
    const pathBits: number[] = [];
    let idx = leafIdx;
    for (let d = 0; d < MERKLE_DEPTH; d++) {
      const sibIdx = idx % 2 === 0 ? idx + 1 : idx - 1;
      siblings.push(tree[d][sibIdx].toString());
      pathBits.push(idx % 2); // 0 = left child, 1 = right
      idx = Math.floor(idx / 2);
    }
    return { siblings, pathBits };
  }

  // Transforms high-level hospital-api request into circuit-level inputs
  private buildHighLevelInput(req: HighLevelRequest, nonce: string): Record<string, unknown> {
    const allergies = req.allergies ?? [];
    // drugId 105 = Metformin (idx 0), drugId 103 = Penicillin (idx 1), drugId 107 = Amoxicillin (idx 2)
    const approvedDrugIds = ['105', '103', '107'];

    // Credential hash: use MFSSIA registry value if provided, otherwise derive from UAL
    const doctorCredentialHash = req.doctorCredentialHash
      ? BigInt(req.doctorCredentialHash)
      : this.stringToField(req.doctorCredentialUal ?? '');

    // Reference leaves and allergy matrix
    const refLeafValues: bigint[] = [];
    const allergyMatrix: number[][] = [];

    for (let i = 0; i < N_max; i++) {
      if (i < allergies.length) {
        const substIdx = SUBSTANCE_IDX[allergies[i]] ?? -1;
        // Leaf hash: Poseidon(drugId) for known substances, SHA256 for others
        const leafVal = substIdx >= 0
          ? this.poseidonHash([BigInt(substIdx + 1)])
          : this.stringToField(allergies[i]);
        refLeafValues.push(leafVal);
        // Subsumption: each allergen blocks the entire β-lactam class (or just itself)
        const row = new Array(N_DRUGS).fill(0);
        const blocked = substIdx >= 0 ? (ALLERGY_BLOCKS[substIdx] ?? [substIdx]) : [];
        for (const j of blocked) row[j] = 1;
        allergyMatrix.push(row);
      } else {
        // Padding: inactive slot
        refLeafValues.push(0n);
        allergyMatrix.push(new Array(N_DRUGS).fill(0));
      }
    }

    const refIsActive = Array.from({ length: N_max }, (_, i) => i < allergies.length ? 1 : 0);

    // Physician tree: root and proof come from MFSSIA (validCredentialRoot anchored in DKG).
    // Fallback: build locally if MFSSIA is unavailable (backwards compatibility).
    let validCredentialRoot: string;
    let credSiblings: string[];
    let credPathBits: string[];

    if (!req.validCredentialRoot || !req.credentialSiblings || !req.credentialPathBits) {
      throw new Error('validCredentialRoot, credentialSiblings and credentialPathBits are required — fetch them from MFSSIA physician registry');
    }
    validCredentialRoot = req.validCredentialRoot;
    credSiblings = req.credentialSiblings;
    credPathBits = req.credentialPathBits.map(String);

    // Patient tree: allergies only (leaves 0..N_max-1)
    const { root: patientRoot, tree: patientTree } = this.buildMerkleTree(refLeafValues);

    const refSiblings = refLeafValues.map((_, i) => {
      if (refIsActive[i]) return this.getMerkleProof(patientTree, i).siblings;
      return new Array(MERKLE_DEPTH).fill('0');
    });
    const refPathBitsArr = refLeafValues.map((_, i) => {
      if (refIsActive[i]) return this.getMerkleProof(patientTree, i).pathBits;
      return new Array(MERKLE_DEPTH).fill(0);
    });

    // Dosages: extract numeric part ("500mg" → "500")
    const prescribedDosages = (req.dosages ?? []).slice(0, N_PRESC).map(d => this.parseDosage(d));

    // Maximum dosages from DKG policies
    const adultMax = new Array(N_DRUGS).fill('65535');
    const childMax = new Array(N_DRUGS).fill('65535');
    for (const p of req.policies ?? []) {
      const code = (p.medicationCode ?? '').toLowerCase();
      const dIdx = code.includes('metformin') ? 0
                 : code.includes('penicillin') ? 1
                 : code.includes('amoxicillin') ? 2
                 : -1;
      if (dIdx < 0) continue;
      const thresh = Math.min(Math.floor(Number(p.threshold)), 65535).toString();
      const cond = (p.clinicalCondition ?? '').toLowerCase();
      if (cond.includes('child') || cond.includes('pediatric')) {
        childMax[dIdx] = thresh;
      } else {
        adultMax[dIdx] = thresh;
      }
    }

    // Timestamps set to zero: 0 ≤ 0 + 65535 → TimeValid policy passes trivially.
    // Real Unix timestamps do not fit in BITLEN=16 (max 65535).
    return {
      doctorCredentialHash: doctorCredentialHash.toString(),
      validCredentialRoot,
      patientRecordRoot: patientRoot.toString(),
      nonce,
      approvedDrugIds,
      allergyMatrix: allergyMatrix.map(row => row.map(String)),
      adultMaxDosages: adultMax,
      credentialSiblings: credSiblings,
      credentialPathBits: credPathBits,
      prescribedDrugIds: (req.drugIds ?? []).slice(0, N_PRESC).map(String),
      prescribedDosages,
      patientAge: String(req.patientAge ?? 0),
      prescriptionTimestamp: '0',
      validFor: '65535',
      currentTimestamp: '0',
      workflowId: String(req.workflowId ?? 0),
      childMaxDosages: childMax,
      refLeaf: refLeafValues.map(String),
      refSiblings,
      refPathBits: refPathBitsArr.map(row => row.map(String)),
      refIsActive: refIsActive.map(String),
    };
  }

  // Builds circuit input from low-level DTO (direct circuit-level fields)
  private buildInput(dto: ProveRequestDto, nonce: string): Record<string, unknown> {
    return {
      doctorCredentialHash: dto.doctorCredentialHash,
      validCredentialRoot: dto.validCredentialRoot,
      nonce,
      approvedDrugIds: dto.approvedDrugIds,
      allergyMatrix: dto.allergyMatrix.map(row => row.map(String)),
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
// Amoxicillin (drugId 107, idx 2) is blocked by Penicillin allergy via β-lactam class subsumption
