/** A fresh TOTP counter must be consumed atomically across all owner sessions. */
export async function consumeTotpCounter(_adminId: number, _matchedStep: number): Promise<void> {
  // Test-first placeholder.
}
