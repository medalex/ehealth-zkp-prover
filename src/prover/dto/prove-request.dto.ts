export class ProveRequestDto {
  // Per-workflow identifier — the circuit derives nonce = Poseidon([workflowId]) internally
  workflowId: number;

  // Doctor credential Merkle proof (computed once per doctor via the helper circuit)
  doctorCredentialHash: string;   // H(credential) as a field element string
  validCredentialRoot: string;    // Poseidon Merkle root of the 8-doctor registry
  credentialSiblings: string[];   // 3 sibling hashes along the Merkle path
  credentialPathBits: number[];   // 3 direction bits: 0 = left, 1 = right

  // Prescription data
  prescribedDrugIds: string[];    // 2 drug IDs (field elements matching approvedDrugIds)
  prescribedDosages: string[];    // 2 dosage values

  // Governance policy inputs sourced from DKG via mfssia-ehealth
  approvedDrugIds: string[];      // 4 governance-approved drug IDs
  allergyMatrix: number[][];      // 3×4 binary matrix: allergyMatrix[a][d] = 1 if allergy row a conflicts with drug column d
  adultMaxDosages: string[];      // 4 maximum dosages for adults (age ≥ 11)
  childMaxDosages: string[];      // 4 maximum dosages for children (age < 11)

  // Patient attributes
  patientAge: number;

  // Timestamps in Unix seconds
  prescriptionTimestamp: number;
  validFor: number;               // Validity window in seconds
  currentTimestamp: number;
}
