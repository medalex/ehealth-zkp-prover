declare module 'circomlibjs' {
  type PoseidonFn = {
    (inputs: bigint[]): Uint8Array;
    F: { toObject(x: Uint8Array): bigint };
  };
  export function buildPoseidon(): Promise<PoseidonFn>;
}
