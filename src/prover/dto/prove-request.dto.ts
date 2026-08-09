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
  maxDosages: string[];           // N_DRUGS governance-approved max dosages per drug

  // Committed contraindication closure (MFSSIA → DKG). Per active slot:
  //   refLeaf[i] = Poseidon(patientField, substanceId[i]+1)  (binds substance to the record)
  //   contra leaf = Poseidon(substanceId[i], prescribedDrug, contraValue[i]) ∈ contraindicationRoot
  contraindicationRoot: string;   // governance closure Merkle root (PUBLIC)
  patientField: string;           // stringToField(patientId) salt for record leaves
  substanceId: number[];          // N_max substance ids (bound to refLeaf)
  contraValue: number[];          // N_max contraindication values from the closure
  contraSiblings: string[][];     // N_max × CONTRA_DEPTH membership siblings
  contraPathBits: number[][];     // N_max × CONTRA_DEPTH membership path bits

  // Unix timestamps in seconds. Both are PUBLIC (read by the verifier) and bound into
  // stmtHash; the freshness check now <= issuanceTime + validFor is done off-circuit.
  issuanceTime: number;
  validFor: number;               // Prescription validity window in seconds

  // N_max patient record reference slots (allergies, lab results)
  // refLeaf[i]      = Poseidon(recordId, recordType, substanceId, ...) — leaf hash
  // refSiblings[i]  = MERKLE_DEPTH sibling hashes for slot i
  // refPathBits[i]  = MERKLE_DEPTH path bits for slot i (0=left, 1=right)
  // Slot activation is NOT supplied: the circuit derives refIsActive[i] = (i < allergyCount)
  // and proves the zero leaf is a member of patientRecordRoot at index allergyCount, with
  // paddingPathBits pinned to the little-endian bits of that index.
  refLeaf: string[];
  refSiblings: string[][];
  refPathBits: number[][];
  allergyCount: number;
  paddingSiblings: string[];      // MERKLE_DEPTH
  paddingPathBits: number[];      // MERKLE_DEPTH

  // N_LAB lab-based clinical policy slots (P3 lab clause — eGFR etc.)
  // labValue[L]         = patient measurement (PRIVATE, trusted prover)
  // labIsActive[L]      = 1 for an active slot, 0 for padding
  // labThreshold[L]     = clinical threshold from DKG (PUBLIC)
  // labRequiredOp[L]    = required (safe) condition: 0=GTE, 1=LTE, 2=EQ, 3=NEQ (PUBLIC)
  // labAppliesToDrug[L] = drugId the policy targets, 0 for padding (PUBLIC)
  // labMetricIdPub[L]   = stringToField(clinicalCondition) — the metric the policy governs,
  //                       0 for padding (PUBLIC). The circuit enforces
  //                       labMetricId[L] === labMetricIdPub[L] and
  //                       labIsActive[L] === (labAppliesToDrug[L] == prescribedDrugIds[0]).
  labValue: string[];
  labIsActive: number[];
  labThreshold: string[];
  labRequiredOp: number[];
  labAppliesToDrug: string[];
  labMetricIdPub: string[];

  // Lab-record membership (MFSSIA → DKG): leaf = Poseidon(patientField, labMetricId[L], labValue[L])
  labRecordRoot: string;
  labMetricId: string[];          // N_LAB
  labRecordSiblings: string[][];  // N_LAB × LAB_DEPTH
  labRecordPathBits: number[][];  // N_LAB × LAB_DEPTH
}
