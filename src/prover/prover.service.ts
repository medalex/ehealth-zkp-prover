import { Injectable, OnModuleInit, ServiceUnavailableException } from '@nestjs/common';
import * as fs from 'fs';
import * as path from 'path';
import { buildPoseidon } from 'circomlibjs';
import { ProveRequestDto } from './dto/prove-request.dto';
import { VerifyRequestDto } from './dto/verify-request.dto';

// Circuit fixed dimensions — must match the compiled prescription_validation_poseidon_merkle.circom
const N_DRUGS = 4;
const N_ALLERGIES = 3;
const N_PRESC = 2;
const MERKLE_DEPTH = 3;

// Public signal indices in the snarkjs output array:
// outputs come first (outcome, stmtHash), then public inputs in declaration order
export const PUB = {
  outcome: 0,
  stmtHash: 1,
  doctorCredentialHash: 2,
  validCredentialRoot: 3,
  nonce: 4,
  approvedDrugIds: [5, 6, 7, 8],
  // allergyMatrix rows 0-2, cols 0-3 in row-major order: indices 9..20
  allergyMatrixStart: 9,
  adultMaxDosages: [21, 22, 23, 24],
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
      // Public inputs
      doctorCredentialHash: dto.doctorCredentialHash,
      validCredentialRoot: dto.validCredentialRoot,
      nonce,
      approvedDrugIds: dto.approvedDrugIds,
      allergyMatrix: dto.allergyMatrix.map(row => row.map(String)),
      adultMaxDosages: dto.adultMaxDosages,
      // Private inputs
      prescribedDrugIds: dto.prescribedDrugIds,
      prescribedDosages: dto.prescribedDosages,
      patientAge: String(dto.patientAge),
      prescriptionTimestamp: String(dto.prescriptionTimestamp),
      validFor: String(dto.validFor),
      currentTimestamp: String(dto.currentTimestamp),
      workflowId: String(dto.workflowId),
      credentialSiblings: dto.credentialSiblings,
      credentialPathBits: dto.credentialPathBits.map(String),
      childMaxDosages: dto.childMaxDosages,
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

// Exported for use in hospital-api and pharmacy-api when parsing publicSignals
export { N_DRUGS, N_ALLERGIES, N_PRESC, MERKLE_DEPTH };
