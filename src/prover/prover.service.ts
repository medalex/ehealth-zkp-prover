import { Injectable, OnModuleInit, ServiceUnavailableException } from '@nestjs/common';
import * as fs from 'fs';
import * as path from 'path';
import { buildPoseidon } from 'circomlibjs';
import { ProveRequestDto } from './dto/prove-request.dto';
import { VerifyRequestDto } from './dto/verify-request.dto';

// Фиксированные размеры схемы — должны совпадать со скомпилированным circom-файлом.
const N_DRUGS = 2;
const N_max = 3;   // число референсных слотов; определяет сложность n_total ≈ n_cred + N_max·n_Merkle + |Pol|·n_range
const N_PRESC = 1;
const MERKLE_DEPTH = 3;

// Индексы публичных сигналов в массиве snarkjs (выходы идут первыми, затем публичные входы):
// outcome(0), stmtHash(1), doctorCredentialHash(2), validCredentialRoot(3), nonce(4),
// approvedDrugIds[2] → 5-6, allergyMatrix[N_max×N_DRUGS=6] → 7-12, adultMaxDosages[2] → 13-14
export const PUB = {
  outcome: 0,
  stmtHash: 1,
  doctorCredentialHash: 2,
  validCredentialRoot: 3,
  nonce: 4,
  approvedDrugIds: [5, 6],
  // allergyMatrix строки 0-2, столбцы 0-1 в row-major порядке: индексы 7..12
  allergyMatrixStart: 7,
  adultMaxDosages: [13, 14],
} as const;

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

  private buildInput(dto: ProveRequestDto, nonce: string): Record<string, unknown> {
    return {
      // Публичные входы
      doctorCredentialHash: dto.doctorCredentialHash,
      validCredentialRoot: dto.validCredentialRoot,
      nonce,
      approvedDrugIds: dto.approvedDrugIds,
      allergyMatrix: dto.allergyMatrix.map(row => row.map(String)),
      adultMaxDosages: dto.adultMaxDosages,
      // Приватные входы — учётные данные врача
      credentialSiblings: dto.credentialSiblings,
      credentialPathBits: dto.credentialPathBits.map(String),
      // Приватные входы — рецепт и пациент
      prescribedDrugIds: dto.prescribedDrugIds,
      prescribedDosages: dto.prescribedDosages,
      patientAge: String(dto.patientAge),
      prescriptionTimestamp: String(dto.prescriptionTimestamp),
      validFor: String(dto.validFor),
      currentTimestamp: String(dto.currentTimestamp),
      workflowId: String(dto.workflowId),
      childMaxDosages: dto.childMaxDosages,
      // Приватные входы — N_max референсных слотов (аллергии и записи пациента)
      refLeaf: dto.refLeaf,
      refSiblings: dto.refSiblings.map(row => row.map(String)),
      refPathBits: dto.refPathBits.map(row => row.map(String)),
      refIsActive: dto.refIsActive.map(String),
    };
  }

  async prove(dto: ProveRequestDto) {
    this.assertArtifacts();

    // nonce is derived from workflowId so the circuit can bind the proof to a specific workflow
    const nonce = this.poseidonHash([BigInt(dto.workflowId)]).toString();

    const input = this.buildInput(dto, nonce);

    const snarkjs = await import('snarkjs');
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
      input,
      this.wasmPath,
      this.zkeyPath,
    );

    return {
      proof,
      publicSignals,
      outcome: parseInt(publicSignals[PUB.outcome]),
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
