import { INV_S_BOX, S_BOX } from "./constants.js";

/**
 * Input: AES state.
 * Output: state after S-Box substitution.
 * Formula: state'[r][c] = SBox[state[r][c]].
 * Reference: FIPS-197 Section 5.1.1.
 * Complexity: O(16).
 */
export function subBytes(state) {
  return state.map((row) => row.map((byte) => S_BOX[byte]));
}

/**
 * Input: AES state.
 * Output: state after inverse S-Box substitution.
 * Formula: state'[r][c] = InvSBox[state[r][c]].
 * Reference: FIPS-197 Section 5.3.2.
 * Complexity: O(16).
 */
export function invSubBytes(state) {
  return state.map((row) => row.map((byte) => INV_S_BOX[byte]));
}
