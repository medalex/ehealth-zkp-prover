export class ProveRequestDto {
  // Workflow identifier — nonce = Poseidon([workflowId]) is computed inside the circuit
  workflowId: number;

  // Merkle proof for the physician credential (computed once at registration)
  doctorCredentialHash: string;   // H(credential) as a field element
  validCredentialRoot: string;    // root_M — registry root (covers physician + patient records)
  credentialSiblings: string[];   // MERKLE_DEPTH sibling hashes
  credentialPathBits: number[];   // MERKLE_DEPTH direction bits (0=left, 1=right)

  // Prescription data
  prescribedDrugIds: string[];    // N_PRESC drug identifiers
  prescribedDosages: string[];    // N_PRESC dosage values

  // Policy parameters T from DKG (governance-approved)
  approvedDrugIds: string[];      // N_DRUGS approved drug identifiers
  allergyMatrix: number[][];      // N_max × N_DRUGS: allergyMatrix[i][j]=1 if slot i contraindicates drug j
  adultMaxDosages: string[];      // N_DRUGS max dosages for adults (age >= 11)
  childMaxDosages: string[];      // N_DRUGS max dosages for children (age < 11)

  // Patient attributes
  patientAge: number;

  // Unix timestamps in seconds
  prescriptionTimestamp: number;
  validFor: number;               // Prescription validity window in seconds
  currentTimestamp: number;

  // N_max patient record reference slots (allergies, lab results)
  // refLeaf[i]      = Poseidon(recordId, recordType, substanceId, ...) — leaf hash
  // refSiblings[i]  = MERKLE_DEPTH sibling hashes for slot i
  // refPathBits[i]  = MERKLE_DEPTH path bits for slot i (0=left, 1=right)
  // refIsActive[i]  = 1 for an active slot, 0 for padding
  refLeaf: string[];
  refSiblings: string[][];
  refPathBits: number[][];
  refIsActive: number[];
}
