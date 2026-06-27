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
  policyDrugIds: string[];        // N_DRUGS drug identifiers covered by policy parameters (dosage limits)
  adultMaxDosages: string[];      // N_DRUGS max dosages for adults (age >= 11)
  childMaxDosages: string[];      // N_DRUGS max dosages for children (age < 11)

  // Committed contraindication closure (MFSSIA → DKG). Per active slot:
  //   refLeaf[i] = Poseidon(patientField, substanceId[i]+1)  (binds substance to the record)
  //   contra leaf = Poseidon(substanceId[i], prescribedDrug, contraValue[i]) ∈ contraindicationRoot
  contraindicationRoot: string;   // governance closure Merkle root (PUBLIC)
  patientField: string;           // stringToField(patientId) salt for record leaves
  substanceId: number[];          // N_max substance ids (bound to refLeaf)
  contraValue: number[];          // N_max contraindication values from the closure
  contraSiblings: string[][];     // N_max × CONTRA_DEPTH membership siblings
  contraPathBits: number[][];     // N_max × CONTRA_DEPTH membership path bits

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

  // N_LAB lab-based clinical policy slots (P6 — eGFR etc.)
  // labValue[L]         = patient measurement (PRIVATE, trusted prover)
  // labIsActive[L]      = 1 for an active slot, 0 for padding
  // labThreshold[L]     = clinical threshold from DKG (PUBLIC)
  // labRequiredOp[L]    = required (safe) condition: 0=GTE, 1=LTE, 2=EQ, 3=NEQ (PUBLIC)
  // labAppliesToDrug[L] = drugId the policy targets, 0 for padding (PUBLIC)
  labValue: string[];
  labIsActive: number[];
  labThreshold: string[];
  labRequiredOp: number[];
  labAppliesToDrug: string[];
}
