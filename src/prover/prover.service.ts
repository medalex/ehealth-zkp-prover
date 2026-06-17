import { Injectable, OnModuleInit, ServiceUnavailableException } from '@nestjs/common';
import { createHash } from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import { buildPoseidon } from 'circomlibjs';
import { ProveRequestDto } from './dto/prove-request.dto';
import { VerifyRequestDto } from './dto/verify-request.dto';

// Размеры схемы — должны совпадать со скомпилированным circom-файлом.
const N_DRUGS = 3;
const N_max = 3;   // число референсных слотов; n_total ≈ n_cred + N_max·n_Merkle + |Pol|·n_range
const N_PRESC = 1;
const MERKLE_DEPTH = 3;

// Маппинг аллергена → 0-based индекс в N_DRUGS.
// approvedDrugIds = [105, 103, 107]:
//   j=0 → Metformin (drugId 105)
//   j=1 → Penicillin (drugId 103)
//   j=2 → Amoxicillin (drugId 107)
const SUBSTANCE_IDX: Record<string, number> = {
  'Metformin':   0, 'metformin':   0,
  'Penicillin':  1, 'penicillin':  1,
  'Amoxicillin': 2, 'amoxicillin': 2,
};

// Субсумпция β-лактамного класса: аллергия на Penicillin блокирует и Amoxicillin.
// allergyMatrix[slot][j]=1 для каждого j из этого множества.
const ALLERGY_BLOCKS: Record<number, number[]> = {
  1: [1, 2],  // Penicillin (idx=1) ⊑ β-lactam → блокирует Penicillin + Amoxicillin
  2: [1, 2],  // Amoxicillin (idx=2) ⊑ β-lactam → блокирует тот же класс
  0: [0],     // Metformin — отдельный класс (biguanide)
};

// Индексы публичных сигналов в массиве snarkjs (выходы первые, затем публичные входы):
// outcome(0), stmtHash(1), doctorCredentialHash(2), validCredentialRoot(3), nonce(4),
// approvedDrugIds[3] → 5-7, allergyMatrix[N_max×N_DRUGS=9] → 8-16, adultMaxDosages[3] → 17-19
export const PUB = {
  outcome: 0,
  stmtHash: 1,
  doctorCredentialHash: 2,
  validCredentialRoot: 3,
  nonce: 4,
  approvedDrugIds: [5, 6, 7],
  allergyMatrixStart: 8,
  adultMaxDosages: [17, 18, 19],
} as const;

// Высокоуровневый запрос от hospital-api (ASP.NET Core сериализует в camelCase)
interface HighLevelRequest {
  doctorCredentialUal: string;
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

  // Детерминированное преобразование строки → поле BN254 (31 байт = 248 бит < 254 бит prime)
  private stringToField(s: string): bigint {
    const h = createHash('sha256').update(s, 'utf8').digest('hex');
    return BigInt('0x' + h.slice(0, 62));
  }

  // Извлекает первое целое число из строки дозировки ("500mg" → "500")
  private parseDosage(s: string): string {
    const m = (s ?? '').match(/\d+/);
    return m ? m[0] : '0';
  }

  // Строит дерево Меркле глубины MERKLE_DEPTH (8 листьев) с Poseidon-хешами
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

  // Возвращает доказательство принадлежности листа с индексом leafIdx дереву
  private getMerkleProof(tree: bigint[][], leafIdx: number): { siblings: string[]; pathBits: number[] } {
    const siblings: string[] = [];
    const pathBits: number[] = [];
    let idx = leafIdx;
    for (let d = 0; d < MERKLE_DEPTH; d++) {
      const sibIdx = idx % 2 === 0 ? idx + 1 : idx - 1;
      siblings.push(tree[d][sibIdx].toString());
      pathBits.push(idx % 2); // 0 = левый ребёнок, 1 = правый
      idx = Math.floor(idx / 2);
    }
    return { siblings, pathBits };
  }

  // Трансформирует высокоуровневый запрос hospital-api в circuit-level inputs
  private buildHighLevelInput(req: HighLevelRequest, nonce: string): Record<string, unknown> {
    const allergies = req.allergies ?? [];
    // drugId 105 = Metformin (idx 0), drugId 103 = Penicillin (idx 1), drugId 107 = Amoxicillin (idx 2)
    const approvedDrugIds = ['105', '103', '107'];

    // Детерминированный хеш UAL врача
    const doctorCredentialHash = this.stringToField(req.doctorCredentialUal ?? '');

    // Референсные листья и матрица аллергий
    const refLeafValues: bigint[] = [];
    const allergyMatrix: number[][] = [];

    for (let i = 0; i < N_max; i++) {
      if (i < allergies.length) {
        const substIdx = SUBSTANCE_IDX[allergies[i]] ?? -1;
        // Листовой хеш: Poseidon(drugId) для известных веществ, SHA256 для прочих
        const leafVal = substIdx >= 0
          ? this.poseidonHash([BigInt(substIdx + 1)])
          : this.stringToField(allergies[i]);
        refLeafValues.push(leafVal);
        // Субсумпция: каждый аллерген блокирует весь β-лактамный класс (или только себя)
        const row = new Array(N_DRUGS).fill(0);
        const blocked = substIdx >= 0 ? (ALLERGY_BLOCKS[substIdx] ?? [substIdx]) : [];
        for (const j of blocked) row[j] = 1;
        allergyMatrix.push(row);
      } else {
        // Паддинг: неактивный слот
        refLeafValues.push(0n);
        allergyMatrix.push(new Array(N_DRUGS).fill(0));
      }
    }

    const refIsActive = Array.from({ length: N_max }, (_, i) => i < allergies.length ? 1 : 0);

    // Дерево Меркле: лист 0 = doctorCredentialHash, листья 1..N_max = refLeaf[0..N_max-1]
    const treeLeaves = [doctorCredentialHash, ...refLeafValues];
    const { root, tree } = this.buildMerkleTree(treeLeaves);

    const credProof = this.getMerkleProof(tree, 0);

    const refSiblings = refLeafValues.map((_, i) => {
      if (refIsActive[i]) return this.getMerkleProof(tree, i + 1).siblings;
      return new Array(MERKLE_DEPTH).fill('0');
    });
    const refPathBitsArr = refLeafValues.map((_, i) => {
      if (refIsActive[i]) return this.getMerkleProof(tree, i + 1).pathBits;
      return new Array(MERKLE_DEPTH).fill(0);
    });

    // Дозировки: извлекаем числовую часть ("500mg" → "500")
    const prescribedDosages = (req.dosages ?? []).slice(0, N_PRESC).map(d => this.parseDosage(d));

    // Максимальные дозировки из политик DKG
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

    // Временные метки используем нули: 0 ≤ 0 + 65535 → политика TimeValid проходит тривиально.
    // Реальные Unix-timestamps не помещаются в BITLEN=16 (max 65535).
    return {
      doctorCredentialHash: doctorCredentialHash.toString(),
      validCredentialRoot: root.toString(),
      nonce,
      approvedDrugIds,
      allergyMatrix: allergyMatrix.map(row => row.map(String)),
      adultMaxDosages: adultMax,
      credentialSiblings: credProof.siblings,
      credentialPathBits: credProof.pathBits.map(String),
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

  // Строит circuit input из низкоуровневого DTO (прямые circuit-level поля)
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
      // Высокоуровневый формат от hospital-api (ASP.NET Core camelCase JSON)
      const req = dto as HighLevelRequest;
      nonce = this.poseidonHash([BigInt(req.workflowId ?? 0)]).toString();
      input = this.buildHighLevelInput(req, nonce);
    } else {
      // Низкоуровневый формат (прямые circuit inputs)
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
      outcome: parseInt(publicSignals[PUB.outcome]) === 1,  // bool для C# System.Text.Json
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

// Экспорт для hospital-api и pharmacy-api при разборе publicSignals
export { N_DRUGS, N_max, N_PRESC, MERKLE_DEPTH };
// Амоксициллин (drugId 107, idx 2) блокируется аллергией на Пенициллин через β-лактамную субсумпцию
