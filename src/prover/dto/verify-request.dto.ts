export class VerifyRequestDto {
  // Groth16 proof object as returned by /prove (pi_a, pi_b, pi_c, protocol, curve)
  proof: Record<string, unknown>;
  // Public signals array as returned by /prove (outputs first, then public inputs)
  publicSignals: string[];
}
