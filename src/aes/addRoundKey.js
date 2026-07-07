import { roundKeyToState } from "./matrix.js";
import { toByte } from "./utils.js";

/**
 * Input: AES state and 16-byte round key.
 * Output: state XORed with round key.
 * Formula: state'[r][c] = state[r][c] XOR keyState[r][c].
 * Reference: FIPS-197 Section 5.1.4.
 * Complexity: O(16).
 */
export function addRoundKey(state, roundKey) {
  const keyState = roundKeyToState(roundKey);
  return state.map((row, rowIndex) => row.map((byte, colIndex) => toByte(byte ^ keyState[rowIndex][colIndex])));
}
