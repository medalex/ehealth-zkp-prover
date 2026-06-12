export class ProveRequestDto {
  // Идентификатор workflow — nonce = Poseidon([workflowId]) вычисляется в схеме
  workflowId: number;

  // Merkle-доказательство для учётной записи врача (вычисляется один раз при регистрации)
  doctorCredentialHash: string;   // H(credential) как элемент поля
  validCredentialRoot: string;    // root_M — корень реестра (включает врача и записи пациента)
  credentialSiblings: string[];   // MERKLE_DEPTH хешей-соседей
  credentialPathBits: number[];   // MERKLE_DEPTH битов направления (0=левый, 1=правый)

  // Данные рецепта
  prescribedDrugIds: string[];    // N_PRESC идентификаторов препаратов
  prescribedDosages: string[];    // N_PRESC значений дозировки

  // Параметры политики T из DKG (governance-approved)
  approvedDrugIds: string[];      // N_DRUGS разрешённых идентификаторов препаратов
  allergyMatrix: number[][];      // N_max × N_DRUGS: allergyMatrix[i][j]=1 если слот i противопоказан с препаратом j
  adultMaxDosages: string[];      // N_DRUGS максимальных дозировок для взрослых (возраст >= 11)
  childMaxDosages: string[];      // N_DRUGS максимальных дозировок для детей (возраст < 11)

  // Атрибуты пациента
  patientAge: number;

  // Временные метки в секундах Unix
  prescriptionTimestamp: number;
  validFor: number;               // Окно действия рецепта в секундах
  currentTimestamp: number;

  // N_max референсных слотов записей пациента (аллергии, лабораторные результаты)
  // refLeaf[i]      = Poseidon(recordId, recordType, substanceId, ...) — листовой хеш
  // refSiblings[i]  = MERKLE_DEPTH хешей-соседей для слота i
  // refPathBits[i]  = MERKLE_DEPTH битов пути для слота i (0=левый, 1=правый)
  // refIsActive[i]  = 1 для активного слота, 0 для паддинга
  refLeaf: string[];
  refSiblings: string[][];
  refPathBits: number[][];
  refIsActive: number[];
}
